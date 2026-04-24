// main.go - Prediction Market Client with Oracle Approval Voting & Heartbeat
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
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
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
    OracleResponseTimeoutHours = 10  // 10 hours for oracles to vote
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

func SaveIdentity(path, password string, identity *PersistedIdentity) error {
    if err := os.MkdirAll(path, 0700); err != nil {
        return fmt.Errorf("failed to create directory: %w", err)
    }
    
    // Clean up resolved markets from ActiveMarkets
    for id, market := range identity.ActiveMarkets {
        if market.Resolved {
            delete(identity.ActiveMarkets, id)
            delete(identity.MarketCreationBlock, id)
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
    
    crypto, err := NewCryptoHelper(password)
    if err != nil {
        return err
    }
    
    encrypted, err := crypto.Encrypt(jsonData)
    if err != nil {
        return err
    }
    
    encPath := filepath.Join(path, "identity.enc")
    saltPath := filepath.Join(path, "identity.salt")
    
    if err := os.WriteFile(encPath, encrypted, 0600); err != nil {
        return err
    }
    if err := os.WriteFile(saltPath, crypto.salt, 0600); err != nil {
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

func (p *PeerNode) Distance(target []byte) int {
    distance := 0
    for i := 0; i < len(p.ID) && i < len(target); i++ {
        xor := p.ID[i] ^ target[i]
        for xor > 0 {
            distance++
            xor &= xor - 1
        }
    }
    return distance
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

func (s *SessionData) AddOracleVote(v *OracleVote) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.OracleVotes[v.ProposalID+":"+hex.EncodeToString(v.OracleKey[:8])] = v
}

func (s *SessionData) GetOracleVotes(proposalID string) []*OracleVote {
    s.mu.RLock()
    defer s.mu.RUnlock()
    var list []*OracleVote
 
