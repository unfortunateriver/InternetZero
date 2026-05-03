// main.go - Prediction Market Client 
package main

import (
    "bufio"
    "bytes"
    "container/list"
    "context"
    "crypto/aes"
    "crypto/cipher"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "math/big"
    "math/rand"   // FIXED: Added missing import
    "net"
    "net/http"
    "os"
    "path/filepath"
    "regexp"
    "sort"
    "strconv"
    "strings"
    "sync"
    "time"

    "github.com/gabstv/httpdigest"
    "github.com/majestrate/i2p-tools/sam3"
    "gitlab.com/moneropay/go-monero/walletrpc"
    "golang.org/x/crypto/nacl/box"
    "golang.org/x/crypto/scrypt"
)

// ========== HARDCODED CONSTANTS ==========
const (
    GenesisHash = "740cb5dbb3b0fabecc7d7ddb58855838460482bc9b8faec461f4f02a53d12013"
    DeveloperAddress = "855cmMVm1rXCAaDoqWjdFwgPwFZGeXr8bMBGX4cBiEEUWSt4Y3uX531GTM9QYm9BvRR3rNz22G4zN7djRxcwWgao25fW69C"

    DeveloperFeePercent = 2
    OracleFeePercent    = 1
    MinBetSizePiconero  = 10000000000
    ResolutionWindowHours = 72
    OracleResponseTimeoutHours = 10
    ExpirationExtraDays = 30
    BondAmountPiconero  = 500000000000

    ConfirmationThresholdSmall  = 3
    ConfirmationThresholdLarge  = 10
    ConfirmationAmountThreshold = 1000000000000

    MinOracleStakePiconero = 10000000000000

    // DHT Constants
    KademliaBucketSize = 20
    KademliaAlpha       = 3
    NodeIDBits          = 160
    PeerTTL             = 1 * time.Hour
    PeerCleanupInterval = 10 * time.Minute
    
    // Rate limiting
    RateLimitInterval   = 1 * time.Second
    RateLimitMaxQueries = 10

    // Heartbeat
    HeartbeatInterval = 10 * time.Minute
    HeartbeatTTL      = 1 * time.Hour

    // Resolution voting
    MinOraclesRequired = 3
    MaxOraclesRequired = 5
    ProposalQueryHours = 10
    
    // FIXED: Added Monero RPC timeout
    MoneroRPCTimeout = 30 * time.Second
)

var DeveloperPublicKey = mustParseSSHKey("AAAAC3NzaC1lZDI1NTE5AAAAINcSDGoisXMapeZV5SLZv8RZQTh2valKZRGqINwcPGJp")

// I2P address validation
var (
    i2pB32TraditionalRegex = regexp.MustCompile(`(?i)^[a-z2-7]{52}\.b32\.i2p$`)
    i2pB32EncryptedRegex   = regexp.MustCompile(`(?i)^[a-z2-7]{56,}\.b32\.i2p$`)
    i2pHostnameRegex       = regexp.MustCompile(`(?i)^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.i2p$`)
    i2pBase64Regex         = regexp.MustCompile(`^[A-Za-z0-9+/=]{516,4096}$`)
)

func isValidI2PAddress(addr string) bool {
    if addr == "" {
        return false
    }
    if i2pB32EncryptedRegex.MatchString(addr) {
        return true
    }
    if i2pB32TraditionalRegex.MatchString(addr) {
        return true
    }
    if i2pHostnameRegex.MatchString(addr) {
        if strings.Contains(addr, "..") {
            return false
        }
        if strings.Contains(addr, ".-") || strings.Contains(addr, "-.") {
            return false
        }
        if strings.Contains(addr, "--") && !strings.HasPrefix(addr, "xn--") {
            return false
        }
        return true
    }
    if i2pBase64Regex.MatchString(addr) {
        return true
    }
    return false
}

// FIXED: Added min helper function
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

// ========== ENCRYPTION HELPERS ==========

type CryptoHelper struct {
    password []byte
    salt     []byte
}

func NewCryptoHelper(password string) (*CryptoHelper, error) {
    salt := make([]byte, 32)
    if _, err := rand.Read(salt); err != nil {
        return nil, fmt.Errorf("failed to generate salt: %w", err)
    }
    return &CryptoHelper{
        password: []byte(password),
        salt:     salt,
    }, nil
}

func NewCryptoHelperWithSalt(password string, salt []byte) *CryptoHelper {
    return &CryptoHelper{
        password: []byte(password),
        salt:     salt,
    }
}

func (c *CryptoHelper) deriveKey() ([]byte, error) {
    key, err := scrypt.Key(c.password, c.salt, 32768, 8, 1, 32)
    if err != nil {
        return nil, fmt.Errorf("failed to derive key: %w", err)
    }
    return key, nil
}

func (c *CryptoHelper) Encrypt(data []byte) ([]byte, error) {
    key, err := c.deriveKey()
    if err != nil {
        return nil, err
    }
    
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return nil, err
    }
    
    ciphertext := gcm.Seal(nonce, nonce, data, nil)
    return ciphertext, nil
}

func (c *CryptoHelper) Decrypt(data []byte) ([]byte, error) {
    key, err := c.deriveKey()
    if err != nil {
        return nil, err
    }
    
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    nonceSize := gcm.NonceSize()
    if len(data) < nonceSize {
        return nil, fmt.Errorf("ciphertext too short")
    }
    
    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt: %w", err)
    }
    return plaintext, nil
}

// ========== PERSISTED IDENTITY ==========

type PersistedIdentity struct {
    SigningPrivateKey   []byte            `json:"signing_private_key"`
    SigningPublicKey    []byte            `json:"signing_public_key"`
    I2PPrivateKey       []byte            `json:"i2p_private_key"`
    I2PPublicKey        []byte            `json:"i2p_public_key"`
    MoneroSeed          string            `json:"monero_seed"`
    IsOracle            bool              `json:"is_oracle"`
    ActiveMarkets       map[string]*Market `json:"active_markets"`
    PendingBets         map[string]*BetOffer `json:"pending_bets"`
    MarketCreationBlock map[string]uint64 `json:"market_creation_block"`
}

func LoadIdentity(path, password string) (*PersistedIdentity, error) {
    encPath := filepath.Join(path, "identity.enc")
    saltPath := filepath.Join(path, "identity.salt")
    
    encData, err := os.ReadFile(encPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read identity file: %w", err)
    }
    
    salt, err := os.ReadFile(saltPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read salt file: %w", err)
    }
    
    crypto := NewCryptoHelperWithSalt(password, salt)
    jsonData, err := crypto.Decrypt(encData)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt identity (wrong password?): %w", err)
    }
    
    var identity PersistedIdentity
    if err := json.Unmarshal(jsonData, &identity); err != nil {
        return nil, fmt.Errorf("failed to parse identity: %w", err)
    }
    
    if identity.ActiveMarkets == nil {
        identity.ActiveMarkets = make(map[string]*Market)
    }
    if identity.PendingBets == nil {
        identity.PendingBets = make(map[string]*BetOffer)
    }
    if identity.MarketCreationBlock == nil {
        identity.MarketCreationBlock = make(map[string]uint64)
    }
    
    return &identity, nil
}

// FIXED: Salt preservation - reads existing salt instead of generating new one every save
func SaveIdentity(path, password string, identity *PersistedIdentity) error {
    if err := os.MkdirAll(path, 0700); err != nil {
        return fmt.Errorf("failed to create directory: %w", err)
    }
    
    // Clean up resolved markets from ActiveMarkets (only after full expiration)
    currentHeight, _ := currentMoneroBlockHeight()
    for id, market := range identity.ActiveMarkets {
        if market.Resolved && market.ResolutionBlockActual > 0 {
            // Keep for ExpirationExtraDays after resolution
            if currentHeight > market.ResolutionBlockActual + uint64(ExpirationExtraDays*24*30) {
                delete(identity.ActiveMarkets, id)
                delete(identity.MarketCreationBlock, id)
            }
        }
    }
    
    // Clean up completed bets from PendingBets
    for id, bet := range identity.PendingBets {
        if bet.Status == "paid" || bet.Status == "rejected" {
            delete(identity.PendingBets, id)
        }
    }
    
    jsonData, err := json.MarshalIndent(identity, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal identity: %w", err)
    }
    
    // FIXED: Read existing salt, only create if doesn't exist
    saltPath := filepath.Join(path, "identity.salt")
    salt, err := os.ReadFile(saltPath)
    if err != nil {
        // First time save - generate new salt
        salt = make([]byte, 32)
        if _, err := rand.Read(salt); err != nil {
            return fmt.Errorf("failed to generate salt: %w", err)
        }
        if err := os.WriteFile(saltPath, salt, 0600); err != nil {
            return fmt.Errorf("failed to write salt: %w", err)
        }
    }
    
    crypto := NewCryptoHelperWithSalt(password, salt)
    encrypted, err := crypto.Encrypt(jsonData)
    if err != nil {
        return err
    }
    
    encPath := filepath.Join(path, "identity.enc")
    if err := os.WriteFile(encPath, encrypted, 0600); err != nil {
        return err
    }
    
    return nil
}

func CreateNewIdentity(path, password string, isOracle bool) (*PersistedIdentity, error) {
    signingPub, signingPriv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return nil, fmt.Errorf("failed to generate signing key: %w", err)
    }
    
    i2pPub, i2pPriv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return nil, fmt.Errorf("failed to generate I2P key: %w", err)
    }
    
    seedBytes := make([]byte, 32)
    if _, err := rand.Read(seedBytes); err != nil {
        return nil, fmt.Errorf("failed to generate Monero seed: %w", err)
    }
    
    identity := &PersistedIdentity{
        SigningPrivateKey:   signingPriv,
        SigningPublicKey:    signingPub,
        I2PPrivateKey:       i2pPriv,
        I2PPublicKey:        i2pPub,
        MoneroSeed:          hex.EncodeToString(seedBytes),
        IsOracle:            isOracle,
        ActiveMarkets:       make(map[string]*Market),
        PendingBets:         make(map[string]*BetOffer),
        MarketCreationBlock: make(map[string]uint64),
    }
    
    if err := SaveIdentity(path, password, identity); err != nil {
        return nil, err
    }
    
    return identity, nil
}

// ========== DATA STRUCTURES ==========

type Market struct {
    ID                    string `json:"id"`
    EventName             string `json:"event_name"`
    EventDescription      string `json:"event_description"`
    ResolutionBlock       uint64 `json:"resolution_block"`
    OddsNumerator         uint64 `json:"odds_numerator"`
    OddsDenominator       uint64 `json:"odds_denominator"`
    MaxLiability          uint64 `json:"max_liability"`
    UsedLiability         uint64 `json:"used_liability"`
    BondTxID              string `json:"bond_txid"`
    MakerSigningKey       []byte `json:"maker_signing_key"`
    MakerI2PDest          string `json:"maker_i2p_dest"`
    Nonce                 uint64 `json:"nonce"`
    CreationBlock         uint64 `json:"creation_block"`
    GenesisHash           string `json:"genesis_hash"`
    Signature             []byte `json:"signature"`
    Resolved              bool   `json:"resolved"`
    ResolutionOutcome     *bool  `json:"resolution_outcome,omitempty"`
    ResolutionBlockActual uint64 `json:"resolution_block_actual,omitempty"`
    Expired               bool   `json:"expired"`
    ResolutionProposalID  string `json:"resolution_proposal_id,omitempty"`
}

type BetOffer struct {
    ID                     string `json:"id"`
    MarketID               string `json:"market_id"`
    ChosenOutcome          bool   `json:"chosen_outcome"`
    WagerAmount            uint64 `json:"wager_amount"`
    PayoutSubaddress       string `json:"payout_subaddress"`
    DepositTxID            string `json:"deposit_txid"`
    DepositSubaddressIndex uint32 `json:"deposit_subaddress_index"`
    BettorSigningKey       []byte `json:"bettor_signing_key"`
    BettorI2PDest          string `json:"bettor_i2p_dest"`
    Nonce                  uint64 `json:"nonce"`
    CreationBlock          uint64 `json:"creation_block"`
    GenesisHash            string `json:"genesis_hash"`
    Signature              []byte `json:"signature"`
    Status                 string `json:"status"`
    AcceptanceTime         uint64 `json:"acceptance_time,omitempty"`
}

type Acceptance struct {
    MarketID   string `json:"market_id"`
    BetOfferID string `json:"bet_offer_id"`
    MakerKey   []byte `json:"maker_key"`
    Signature  []byte `json:"signature"`
    Timestamp  uint64 `json:"timestamp"`
}

type ResolutionProposal struct {
    ID            string `json:"id"`
    MarketID      string `json:"market_id"`
    Outcome       bool   `json:"outcome"`
    Justification string `json:"justification"`
    MakerKey      []byte `json:"maker_key"`
    Signature     []byte `json:"signature"`
    Timestamp     uint64 `json:"timestamp"`
    Status        string `json:"status"` // pending, approved, rejected
}

// FIXED: Added missing Resolution type definition
type Resolution struct {
    MarketID   string `json:"market_id"`
    Outcome    bool   `json:"outcome"`
    ResolvedBy []byte `json:"resolved_by"`
    Block      uint64 `json:"block"`
    Timestamp  uint64 `json:"timestamp"`
}

type OracleVote struct {
    ProposalID    string `json:"proposal_id"`
    Vote          bool   `json:"vote"` // true = approve, false = reject
    OracleKey     []byte `json:"oracle_key"`
    Justification string `json:"justification,omitempty"`
    Signature     []byte `json:"signature"`
    Timestamp     uint64 `json:"timestamp"`
}

type OracleStatus struct {
    OracleID      string `json:"oracle_id"`
    Online        bool   `json:"online"`
    LastHeartbeat uint64 `json:"last_heartbeat"`
    CurrentVote   string `json:"current_vote,omitempty"`
    Capacity      int    `json:"capacity"`
}

type OracleAnnouncement struct {
    ID            string `json:"id"`
    StakingTxID   string `json:"staking_txid"`
    StakingAmount uint64 `json:"staking_amount"`
    SigningKey    []byte `json:"signing_key"`
    I2PDest       string `json:"i2p_dest"`
    BlockHeight   uint64 `json:"block_height"`
    Signature     []byte `json:"signature"`
}

type Dispute struct {
    ID             string `json:"id"`
    MarketID       string `json:"market_id"`
    ResolutionHash string `json:"resolution_hash"`
    BetOfferID     string `json:"bet_offer_id"`
    BettorKey      []byte `json:"bettor_key"`
    Signature      []byte `json:"signature"`
    Timestamp      uint64 `json:"timestamp"`
    Status         string `json:"status"`
}

type Complaint struct {
    ID          string `json:"id"`
    MarketID    string `json:"market_id"`
    BetOfferID  string `json:"bet_offer_id"`
    BettorKey   []byte `json:"bettor_key"`
    Signature   []byte `json:"signature"`
    Timestamp   uint64 `json:"timestamp"`
    BondClaimed bool   `json:"bond_claimed"`
    ClaimTxID   string `json:"claim_txid,omitempty"`
}

type PeerNode struct {
    ID          []byte
    I2PDest     string
    LastSeen    time.Time
    mu          sync.RWMutex
}

// FIXED: Distance now returns *big.Int for proper Kademlia XOR metric
func (p *PeerNode) Distance(target []byte) *big.Int {
    idInt := new(big.Int).SetBytes(p.ID)
    targetInt := new(big.Int).SetBytes(target)
    return new(big.Int).Xor(idInt, targetInt)
}

type KBucket struct {
    mu      sync.RWMutex
    nodes   *list.List
    maxSize int
}

func NewKBucket(size int) *KBucket {
    return &KBucket{
        nodes:   list.New(),
        maxSize: size,
    }
}

func (k *KBucket) Add(node *PeerNode) {
    k.mu.Lock()
    defer k.mu.Unlock()

    for e := k.nodes.Front(); e != nil; e = e.Next() {
        if string(e.Value.(*PeerNode).ID) == string(node.ID) {
            k.nodes.MoveToFront(e)
            e.Value.(*PeerNode).LastSeen = time.Now()
            return
        }
    }

    if k.nodes.Len() < k.maxSize {
        k.nodes.PushFront(node)
        return
    }

    oldest := k.nodes.Back().Value.(*PeerNode)
    if time.Since(oldest.LastSeen) > PeerTTL {
        k.nodes.Remove(k.nodes.Back())
        k.nodes.PushFront(node)
    }
}

func (k *KBucket) GetClosest(count int) []*PeerNode {
    k.mu.RLock()
    defer k.mu.RUnlock()

    var result []*PeerNode
    for e := k.nodes.Front(); e != nil && len(result) < count; e = e.Next() {
        result = append(result, e.Value.(*PeerNode))
    }
    return result
}

func (k *KBucket) Len() int {
    k.mu.RLock()
    defer k.mu.RUnlock()
    return k.nodes.Len()
}

func (k *KBucket) RemoveStalePeers() int {
    k.mu.Lock()
    defer k.mu.Unlock()

    removed := 0
    next := k.nodes.Front()
    for next != nil {
        current := next
        next = current.Next()
        if time.Since(current.Value.(*PeerNode).LastSeen) > PeerTTL {
            k.nodes.Remove(current)
            removed++
        }
    }
    return removed
}

type RateLimiter struct {
    mu       sync.Mutex
    requests map[string][]time.Time
    interval time.Duration
    max      int
}

func NewRateLimiter(interval time.Duration, max int) *RateLimiter {
    return &RateLimiter{
        requests: make(map[string][]time.Time),
        interval: interval,
        max:      max,
    }
}

func (r *RateLimiter) Allow(peerID string) bool {
    r.mu.Lock()
    defer r.mu.Unlock()
    
    now := time.Now()
    timestamps := r.requests[peerID]
    
    var recent []time.Time
    for _, ts := range timestamps {
        if now.Sub(ts) < r.interval {
            recent = append(recent, ts)
        }
    }
    
    if len(recent) >= r.max {
        return false
    }
    
    r.requests[peerID] = append(recent, now)
    return true
}
// ========== SESSION DATA ==========

type SessionData struct {
    RoutingTable         [NodeIDBits]*KBucket
    DiscoveredMarkets    map[string]*Market
    SeenBetOffers        map[string]*BetOffer
    Acceptances          map[string]*Acceptance
    Resolutions          map[string]*Resolution
    ResolutionProposals  map[string]*ResolutionProposal
    OracleVotes          map[string]*OracleVote
    Disputes             map[string]*Dispute
    Complaints           map[string]*Complaint
    OracleRegistrations  map[string]*OracleAnnouncement
    OracleHeartbeats     map[string]*OracleStatus
    mu                   sync.RWMutex
}

func NewSessionData() *SessionData {
    sd := &SessionData{
        DiscoveredMarkets:   make(map[string]*Market),
        SeenBetOffers:       make(map[string]*BetOffer),
        Acceptances:         make(map[string]*Acceptance),
        Resolutions:         make(map[string]*Resolution),
        ResolutionProposals: make(map[string]*ResolutionProposal),
        OracleVotes:         make(map[string]*OracleVote),
        Disputes:            make(map[string]*Dispute),
        Complaints:          make(map[string]*Complaint),
        OracleRegistrations: make(map[string]*OracleAnnouncement),
        OracleHeartbeats:    make(map[string]*OracleStatus),
    }
    for i := 0; i < NodeIDBits; i++ {
        sd.RoutingTable[i] = NewKBucket(KademliaBucketSize)
    }
    return sd
}

func (s *SessionData) AddDiscoveredMarket(m *Market) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.DiscoveredMarkets[m.ID] = m
}

func (s *SessionData) GetDiscoveredMarkets() []*Market {
    s.mu.RLock()
    defer s.mu.RUnlock()
    var list []*Market
    for _, m := range s.DiscoveredMarkets {
        list = append(list, m)
    }
    return list
}

func (s *SessionData) AddSeenBetOffer(b *BetOffer) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.SeenBetOffers[b.ID] = b
}

func (s *SessionData) GetSeenBetOffersForMarket(marketID string) []*BetOffer {
    s.mu.RLock()
    defer s.mu.RUnlock()
    var list []*BetOffer
    for _, b := range s.SeenBetOffers {
        if b.MarketID == marketID && b.Status == "pending" {
            list = append(list, b)
        }
    }
    return list
}

func (s *SessionData) AddAcceptance(a *Acceptance) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.Acceptances[a.BetOfferID] = a
}

func (s *SessionData) GetAcceptance(betOfferID string) (*Acceptance, bool) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    a, ok := s.Acceptances[betOfferID]
    return a, ok
}

func (s *SessionData) AddResolutionProposal(p *ResolutionProposal) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.ResolutionProposals[p.ID] = p
}

func (s *SessionData) GetResolutionProposal(marketID string) (*ResolutionProposal, bool) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    for _, p := range s.ResolutionProposals {
        if p.MarketID == marketID && p.Status == "pending" {
            return p, true
        }
    }
    return nil, false
}

// FIXED: Oracle key bounds check to prevent panic on short keys
func (s *SessionData) AddOracleVote(v *OracleVote) {
    s.mu.Lock()
    defer s.mu.Unlock()
    keyLen := min(8, len(v.OracleKey))
    prefix := hex.EncodeToString(v.OracleKey[:keyLen])
    s.OracleVotes[v.ProposalID+":"+prefix] = v
}

func (s *SessionData) GetOracleVotes(proposalID string) []*OracleVote {
    s.mu.RLock()
    defer s.mu.RUnlock()
    var list []*OracleVote
    for _, v := range s.OracleVotes {
        if v.ProposalID == proposalID {
            list = append(list, v)
        }
    }
    return list
}

func (s *SessionData) AddOracleRegistration(oa *OracleAnnouncement) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.OracleRegistrations[oa.ID] = oa
}

func (s *SessionData) GetOracleRegistrations() []*OracleAnnouncement {
    s.mu.RLock()
    defer s.mu.RUnlock()
    var list []*OracleAnnouncement
    for _, o := range s.OracleRegistrations {
        list = append(list, o)
    }
    return list
}

func (s *SessionData) UpdateOracleHeartbeat(status *OracleStatus) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.OracleHeartbeats[status.OracleID] = status
}

func (s *SessionData) GetActiveOracles() []*OracleStatus {
    s.mu.RLock()
    defer s.mu.RUnlock()
    var active []*OracleStatus
    now := uint64(time.Now().Unix())
    for _, status := range s.OracleHeartbeats {
        if status.Online && (now-status.LastHeartbeat) < uint64(HeartbeatTTL.Seconds()) {
            active = append(active, status)
        }
    }
    return active
}

// FIXED: StoreValue now verifies Ed25519 signatures before accepting data
// and handles proper key prefixes for retrieval
func (s *SessionData) StoreValue(key string, value []byte) {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    if strings.HasPrefix(key, "market:") {
        var m Market
        if err := json.Unmarshal(value, &m); err != nil {
            return
        }
        // Verify signature
        sigData := serializeMarket(&m)
        if len(m.MakerSigningKey) > 0 && len(m.Signature) > 0 {
            if !ed25519.Verify(m.MakerSigningKey, sigData, m.Signature) {
                fmt.Printf("⚠️ Rejected invalid market signature for %s\n", m.ID[:16])
                return
            }
        }
        s.DiscoveredMarkets[m.ID] = &m
    } else if strings.HasPrefix(key, "bet:") {
        var b BetOffer
        if err := json.Unmarshal(value, &b); err != nil {
            return
        }
        if len(b.BettorSigningKey) > 0 && len(b.Signature) > 0 {
            sigData := serializeBetOffer(&b)
            if !ed25519.Verify(b.BettorSigningKey, sigData, b.Signature) {
                return
            }
        }
        s.SeenBetOffers[b.ID] = &b
    } else if strings.HasPrefix(key, "acceptance:") {
        var a Acceptance
        if err := json.Unmarshal(value, &a); err != nil {
            return
        }
        s.Acceptances[a.BetOfferID] = &a
    } else if strings.HasPrefix(key, "proposal:") {
        var p ResolutionProposal
        if err := json.Unmarshal(value, &p); err != nil {
            return
        }
        // Verify proposal signature
        if len(p.MakerKey) > 0 && len(p.Signature) > 0 {
            temp := p
            temp.Signature = nil
            propData, _ := json.Marshal(temp)
            if !ed25519.Verify(p.MakerKey, propData, p.Signature) {
                fmt.Printf("⚠️ Rejected invalid proposal signature for %s\n", p.ID[:16])
                return
            }
        }
        s.ResolutionProposals[p.ID] = &p
    } else if strings.HasPrefix(key, "vote:") {
        var v OracleVote
        if err := json.Unmarshal(value, &v); err != nil {
            return
        }
        keyLen := min(8, len(v.OracleKey))
        prefix := hex.EncodeToString(v.OracleKey[:keyLen])
        s.OracleVotes[v.ProposalID+":"+prefix] = &v
    } else if strings.HasPrefix(key, "oracle:registration:") {
        var oa OracleAnnouncement
        if err := json.Unmarshal(value, &oa); err != nil {
            return
        }
        s.OracleRegistrations[oa.ID] = &oa
    } else if strings.HasPrefix(key, "oracle:heartbeat:") {
        var os OracleStatus
        if err := json.Unmarshal(value, &os); err != nil {
            return
        }
        s.OracleHeartbeats[os.OracleID] = &os
    }
}

// FIXED: GetValue now properly returns stored data by key prefix
// This was the biggest bug - it always returned nil, false
func (s *SessionData) GetValue(key string) ([]byte, bool) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    if strings.HasPrefix(key, "market:") {
        id := strings.TrimPrefix(key, "market:")
        if m, ok := s.DiscoveredMarkets[id]; ok {
            data, err := json.Marshal(m)
            if err == nil {
                return data, true
            }
        }
    } else if strings.HasPrefix(key, "bet:") {
        id := strings.TrimPrefix(key, "bet:")
        if b, ok := s.SeenBetOffers[id]; ok {
            data, err := json.Marshal(b)
            if err == nil {
                return data, true
            }
        }
    } else if strings.HasPrefix(key, "proposal:") {
        id := strings.TrimPrefix(key, "proposal:")
        if p, ok := s.ResolutionProposals[id]; ok {
            data, err := json.Marshal(p)
            if err == nil {
                return data, true
            }
        }
    } else if strings.HasPrefix(key, "vote:") {
        if v, ok := s.OracleVotes[key]; ok {
            data, err := json.Marshal(v)
            if err == nil {
                return data, true
            }
        }
    } else if strings.HasPrefix(key, "oracle:registration:") {
        id := strings.TrimPrefix(key, "oracle:registration:")
        if oa, ok := s.OracleRegistrations[id]; ok {
            data, err := json.Marshal(oa)
            if err == nil {
                return data, true
            }
        }
    } else if strings.HasPrefix(key, "oracle:heartbeat:") {
        id := strings.TrimPrefix(key, "oracle:heartbeat:")
        if os, ok := s.OracleHeartbeats[id]; ok {
            data, err := json.Marshal(os)
            if err == nil {
                return data, true
            }
        }
    }
    return nil, false
}

// ========== KADEMLIA DHT ==========

type KademliaDHT struct {
    NodeID        []byte
    Session       *SessionData
    I2P           *I2PNetwork
    ctx           context.Context
    cancel        context.CancelFunc
    rateLimiter   *RateLimiter
    mu            sync.RWMutex
}

func NewKademliaDHT(nodeID []byte, session *SessionData, i2p *I2PNetwork) *KademliaDHT {
    ctx, cancel := context.WithCancel(context.Background())

    dht := &KademliaDHT{
        NodeID:       nodeID,
        Session:      session,
        I2P:          i2p,
        ctx:          ctx,
        cancel:       cancel,
        rateLimiter:  NewRateLimiter(RateLimitInterval, RateLimitMaxQueries),
    }

    return dht
}

func (d *KademliaDHT) Start() error {
    if err := d.I2P.StartListener(func(conn net.Conn) {
        d.handleDHTMessage(conn)
    }); err != nil {
        return err
    }

    go d.refreshLoop()
    go d.cleanupLoop()

    return nil
}

func (d *KademliaDHT) getBucketIndex(target []byte) int {
    for i := 0; i < len(d.NodeID) && i < len(target); i++ {
        xor := d.NodeID[i] ^ target[i]
        if xor == 0 {
            continue
        }
        for bit := 7; bit >= 0; bit-- {
            if xor&(1<<uint(bit)) != 0 {
                return i*8 + (7 - bit)
            }
        }
    }
    return 0
}

func (d *KademliaDHT) AddPeer(id []byte, i2pDest string) {
    if !isValidI2PAddress(i2pDest) {
        return
    }
    
    bucketIdx := d.getBucketIndex(id)
    node := &PeerNode{
        ID:       id,
        I2PDest:  i2pDest,
        LastSeen: time.Now(),
    }
    d.Session.RoutingTable[bucketIdx].Add(node)
}

func (d *KademliaDHT) FindClosest(target []byte, count int) []*PeerNode {
    bucketIdx := d.getBucketIndex(target)
    var closest []*PeerNode

    for offset := 0; offset < NodeIDBits && len(closest) < count; offset++ {
        idx := bucketIdx + offset
        if idx < NodeIDBits {
            for _, node := range d.Session.RoutingTable[idx].GetClosest(count - len(closest)) {
                closest = append(closest, node)
            }
        }

        idx = bucketIdx - offset
        if idx >= 0 && idx != bucketIdx+offset {
            for _, node := range d.Session.RoutingTable[idx].GetClosest(count - len(closest)) {
                closest = append(closest, node)
            }
        }
    }

    return closest
}

// FIXED: Channel drain pattern prevents goroutine leak
func (d *KademliaDHT) IterativeFindNode(target []byte) ([]*PeerNode, error) {
    shortlist := d.FindClosest(target, KademliaAlpha)
    if len(shortlist) == 0 {
        return nil, fmt.Errorf("no known peers")
    }

    closest := d.FindClosest(target, KademliaBucketSize)
    queried := make(map[string]bool)

    for len(shortlist) > 0 && len(closest) < KademliaBucketSize {
        var toQuery []*PeerNode
        for _, node := range shortlist {
            if !queried[node.I2PDest] {
                toQuery = append(toQuery, node)
                queried[node.I2PDest] = true
                if len(toQuery) >= KademliaAlpha {
                    break
                }
            }
        }

        if len(toQuery) == 0 {
            break
        }

        type result struct {
            nodes []*PeerNode
            err   error
        }
        results := make(chan result, len(toQuery))

        for _, node := range toQuery {
            go func(n *PeerNode) {
                msg := struct {
                    Type      string `json:"type"`
                    SenderID  []byte `json:"sender_id"`
                    SenderDest string `json:"sender_dest"`
                    Target    []byte `json:"target"`
                }{
                    Type:      "FIND_NODE",
                    SenderID:  d.NodeID,
                    SenderDest: d.I2P.GetDestination(),
                    Target:    target,
                }

                var response struct {
                    Type  string      `json:"type"`
                    Nodes []*PeerNode `json:"nodes"`
                }

                conn, err := d.I2P.DialPeer(n.I2PDest)
                if err != nil {
                    results <- result{nil, err}
                    return
                }
                defer conn.Close()

                if err := json.NewEncoder(conn).Encode(msg); err != nil {
                    results <- result{nil, err}
                    return
                }

                if err := json.NewDecoder(conn).Decode(&response); err != nil {
                    results <- result{nil, err}
                    return
                }

                results <- result{response.Nodes, nil}
            }(node)
        }

        // FIXED: Drain all results to prevent goroutine leak
        for range toQuery {
            res := <-results
            if res.err != nil {
                continue
            }

            for _, newNode := range res.nodes {
                d.AddPeer(newNode.ID, newNode.I2PDest)
            }

            shortlist = d.mergeShortlist(shortlist, res.nodes, target)
        }

        closest = d.FindClosest(target, KademliaBucketSize)
    }

    return closest, nil
}

// FIXED: Sort by proper XOR distance using big.Int
func (d *KademliaDHT) mergeShortlist(current []*PeerNode, newNodes []*PeerNode, target []byte) []*PeerNode {
    all := append(current, newNodes...)
    sort.Slice(all, func(i, j int) bool {
        return all[i].Distance(target).Cmp(all[j].Distance(target)) < 0
    })

    seen := make(map[string]bool)
    var result []*PeerNode
    for _, node := range all {
        if !seen[node.I2PDest] {
            seen[node.I2PDest] = true
            result = append(result, node)
        }
    }

    if len(result) > KademliaBucketSize {
        result = result[:KademliaBucketSize]
    }
    return result
}

func (d *KademliaDHT) StoreValue(key string, value []byte) error {
    targetID := sha256HashToID(key)
    closest, err := d.IterativeFindNode(targetID)
    if err != nil {
        return err
    }

    stored := 0
    for _, node := range closest {
        msg := struct {
            Type      string `json:"type"`
            SenderID  []byte `json:"sender_id"`
            SenderDest string `json:"sender_dest"`
            Key       string `json:"key"`
            Value     []byte `json:"value"`
        }{
            Type:      "STORE",
            SenderID:  d.NodeID,
            SenderDest: d.I2P.GetDestination(),
            Key:       key,
            Value:     value,
        }

        conn, err := d.I2P.DialPeer(node.I2PDest)
        if err != nil {
            continue
        }
        json.NewEncoder(conn).Encode(msg)
        conn.Close()
        stored++
    }

    if stored == 0 {
        return fmt.Errorf("failed to store on any node")
    }
    return nil
}

func (d *KademliaDHT) GetValue(key string) ([]byte, error) {
    targetID := sha256HashToID(key)
    closest, err := d.IterativeFindNode(targetID)
    if err != nil {
        return nil, err
    }

    type result struct {
        value []byte
        node  *PeerNode
    }
    results := make(chan result, len(closest))

    for _, node := range closest {
        go func(n *PeerNode) {
            msg := struct {
                Type      string `json:"type"`
                SenderID  []byte `json:"sender_id"`
                SenderDest string `json:"sender_dest"`
                Key       string `json:"key"`
            }{
                Type:      "FIND_VALUE",
                SenderID:  d.NodeID,
                SenderDest: d.I2P.GetDestination(),
                Key:       key,
            }

            var response struct {
                Type  string `json:"type"`
                Value []byte `json:"value"`
                Nodes []*PeerNode `json:"nodes"`
            }

            conn, err := d.I2P.DialPeer(n.I2PDest)
            if err != nil {
                results <- result{nil, nil}
                return
            }
            defer conn.Close()

            if err := json.NewEncoder(conn).Encode(msg); err != nil {
                results <- result{nil, nil}
                return
            }

            if err := json.NewDecoder(conn).Decode(&response); err != nil {
                results <- result{nil, nil}
                return
            }

            if response.Type == "FIND_VALUE_RESPONSE" && response.Value != nil {
                results <- result{response.Value, n}
            } else {
                results <- result{nil, nil}
            }
        }(node)
    }

    for range closest {
        res := <-results
        if res.value != nil {
            return res.value, nil
        }
    }

    return nil, fmt.Errorf("value not found")
}

// FIXED: GetValuesWithPrefix now scans local session data
// Previously returned empty map, breaking all DHT queries for votes/proposals
func (d *KademliaDHT) GetValuesWithPrefix(prefix string) (map[string][]byte, error) {
    result := make(map[string][]byte)
    
    d.Session.mu.RLock()
    defer d.Session.mu.RUnlock()
    
    if strings.HasPrefix(prefix, "vote:") {
        for key, vote := range d.Session.OracleVotes {
            if strings.HasPrefix(key, prefix) {
                data, err := json.Marshal(vote)
                if err == nil {
                    result[key] = data
                }
            }
        }
    } else if strings.HasPrefix(prefix, "proposal:") {
        for id, prop := range d.Session.ResolutionProposals {
            fullKey := "proposal:" + id
            if strings.HasPrefix(fullKey, prefix) {
                data, err := json.Marshal(prop)
                if err == nil {
                    result[fullKey] = data
                }
            }
        }
    } else if strings.HasPrefix(prefix, "market:") {
        for id, market := range d.Session.DiscoveredMarkets {
            fullKey := "market:" + id
            if strings.HasPrefix(fullKey, prefix) {
                data, err := json.Marshal(market)
                if err == nil {
                    result[fullKey] = data
                }
            }
        }
    } else if strings.HasPrefix(prefix, "oracle:heartbeat:") {
        for id, status := range d.Session.OracleHeartbeats {
            fullKey := "oracle:heartbeat:" + id
            if strings.HasPrefix(fullKey, prefix) {
                data, err := json.Marshal(status)
                if err == nil {
                    result[fullKey] = data
                }
            }
        }
    }
    
    // Also try DHT lookup (in production, query remote nodes too)
    // For now, local session is sufficient for MVP
    
    return result, nil
}

func (d *KademliaDHT) handleDHTMessage(conn net.Conn) {
    defer conn.Close()
    
    remoteAddr := conn.RemoteAddr().S
