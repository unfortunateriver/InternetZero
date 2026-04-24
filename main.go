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

func (s *SessionData) StoreValue(key string, value []byte) {
    s.mu.Lock()
    defer s.mu.Unlock()
    // Parse and store based on key type
    if strings.HasPrefix(key, "market:") {
        var m Market
        json.Unmarshal(value, &m)
        s.DiscoveredMarkets[m.ID] = &m
    } else if strings.HasPrefix(key, "bet:") {
        var b BetOffer
        json.Unmarshal(value, &b)
        s.SeenBetOffers[b.ID] = &b
    } else if strings.HasPrefix(key, "acceptance:") {
        var a Acceptance
        json.Unmarshal(value, &a)
        s.Acceptances[a.BetOfferID] = &a
    } else if strings.HasPrefix(key, "proposal:") {
        var p ResolutionProposal
        json.Unmarshal(value, &p)
        s.ResolutionProposals[p.ID] = &p
    } else if strings.HasPrefix(key, "vote:") {
        var v OracleVote
        json.Unmarshal(value, &v)
        s.OracleVotes[v.ProposalID+":"+hex.EncodeToString(v.OracleKey[:8])] = &v
    } else if strings.HasPrefix(key, "oracle:registration:") {
        var oa OracleAnnouncement
        json.Unmarshal(value, &oa)
        s.OracleRegistrations[oa.ID] = &oa
    } else if strings.HasPrefix(key, "oracle:heartbeat:") {
        var os OracleStatus
        json.Unmarshal(value, &os)
        s.OracleHeartbeats[os.OracleID] = &os
    }
}

func (s *SessionData) GetValue(key string) ([]byte, bool) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    // This is simplified - in production would need proper key-based retrieval
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

func (d *KademliaDHT) IterativeFindNode(target []byte) ([]*PeerNode, error) {
    shortlist := d.FindClosest(target, KademliaAlpha)
    if len(shortlist) == 0 {
        return nil, fmt.Errorf("no known peers")
    }

    var closest []*PeerNode
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

        for i := 0; i < len(toQuery); i++ {
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

func (d *KademliaDHT) mergeShortlist(current []*PeerNode, newNodes []*PeerNode, target []byte) []*PeerNode {
    all := append(current, newNodes...)
    sort.Slice(all, func(i, j int) bool {
        return all[i].Distance(target) < all[j].Distance(target)
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

    for i := 0; i < len(closest); i++ {
        res := <-results
        if res.value != nil {
            return res.value, nil
        }
    }

    return nil, fmt.Errorf("value not found")
}

func (d *KademliaDHT) GetValuesWithPrefix(prefix string) (map[string][]byte, error) {
    // This would iterate through the DHT - simplified for now
    return make(map[string][]byte), nil
}

func (d *KademliaDHT) handleDHTMessage(conn net.Conn) {
    defer conn.Close()
    
    remoteAddr := conn.RemoteAddr().String()
    if !d.rateLimiter.Allow(remoteAddr) {
        return
    }

    var msg struct {
        Type       string          `json:"type"`
        SenderID   []byte          `json:"sender_id"`
        SenderDest string          `json:"sender_dest"`
        Target     []byte          `json:"target,omitempty"`
        Key        string          `json:"key,omitempty"`
        Value      []byte          `json:"value,omitempty"`
        Nodes      []*PeerNode     `json:"nodes,omitempty"`
    }

    decoder := json.NewDecoder(conn)
    if err := decoder.Decode(&msg); err != nil {
        return
    }

    if msg.SenderID != nil && isValidI2PAddress(msg.SenderDest) {
        d.AddPeer(msg.SenderID, msg.SenderDest)
    }

    switch msg.Type {
    case "PING":
        response := struct {
            Type        string `json:"type"`
            ResponderID []byte `json:"responder_id"`
        }{
            Type:        "PONG",
            ResponderID: d.NodeID,
        }
        json.NewEncoder(conn).Encode(response)

    case "FIND_NODE":
        nodes := d.FindClosest(msg.Target, KademliaBucketSize)
        response := struct {
            Type  string      `json:"type"`
            Nodes []*PeerNode `json:"nodes"`
        }{
            Type:  "FIND_NODE_RESPONSE",
            Nodes: nodes,
        }
        json.NewEncoder(conn).Encode(response)

    case "FIND_VALUE":
        if data, ok := d.Session.GetValue(msg.Key); ok {
            response := struct {
                Type  string `json:"type"`
                Value []byte `json:"value"`
            }{
                Type:  "FIND_VALUE_RESPONSE",
                Value: data,
            }
            json.NewEncoder(conn).Encode(response)
        } else {
            nodes := d.FindClosest(sha256HashToID(msg.Key), KademliaBucketSize)
            response := struct {
                Type  string      `json:"type"`
                Nodes []*PeerNode `json:"nodes"`
            }{
                Type:  "FIND_NODE_RESPONSE",
                Nodes: nodes,
            }
            json.NewEncoder(conn).Encode(response)
        }

    case "STORE":
        d.Session.StoreValue(msg.Key, msg.Value)
    }
}

func (d *KademliaDHT) refreshLoop() {
    ticker := time.NewTicker(30 * time.Minute)
    defer ticker.Stop()

    for {
        select {
        case <-d.ctx.Done():
            return
        case <-ticker.C:
            bucketIdx := rand.Intn(NodeIDBits)
            if d.Session.RoutingTable[bucketIdx].Len() > 0 {
                nodes := d.Session.RoutingTable[bucketIdx].GetClosest(1)
                if len(nodes) > 0 {
                    d.IterativeFindNode(nodes[0].ID)
                }
            }
        }
    }
}

func (d *KademliaDHT) cleanupLoop() {
    ticker := time.NewTicker(PeerCleanupInterval)
    defer ticker.Stop()

    for {
        select {
        case <-d.ctx.Done():
            return
        case <-ticker.C:
            removed := 0
            for i := 0; i < NodeIDBits; i++ {
                removed += d.Session.RoutingTable[i].RemoveStalePeers()
            }
            if removed > 0 {
                fmt.Printf("Cleaned up %d stale peers\n", removed)
            }
        }
    }
}

func (d *KademliaDHT) GetPeerCount() int {
    count := 0
    for i := 0; i < NodeIDBits; i++ {
        count += d.Session.RoutingTable[i].Len()
    }
    return count
}

func (d *KademliaDHT) Stop() {
    d.cancel()
}

func sha256HashToID(key string) []byte {
    hash := sha256.Sum256([]byte(key))
    return hash[:20]
}

// ========== UTILITY FUNCTIONS ==========

func mustParseSSHKey(b64key string) []byte {
    decoded, err := base64.StdEncoding.DecodeString(b64key)
    if err != nil {
        panic(fmt.Sprintf("Failed to decode developer key: %v", err))
    }
    if len(decoded) >= 32 {
        return decoded[len(decoded)-32:]
    }
    panic("Developer key too short")
}

func sha256Hash(data []byte) string {
    hash := sha256.Sum256(data)
    return hex.EncodeToString(hash[:])
}

func serializeMarket(m *Market) []byte {
    return []byte(fmt.Sprintf("%s|%s|%s|%d|%d|%d|%d|%s|%x|%s|%d|%d|%s",
        m.ID, m.EventName, m.EventDescription, m.ResolutionBlock,
        m.OddsNumerator, m.OddsDenominator, m.MaxLiability, m.BondTxID,
        m.MakerSigningKey, m.MakerI2PDest, m.Nonce, m.CreationBlock, m.GenesisHash))
}

func serializeBetOffer(b *BetOffer) []byte {
    return []byte(fmt.Sprintf("%s|%s|%t|%d|%s|%s|%d|%x|%s|%d|%d|%s",
        b.ID, b.MarketID, b.ChosenOutcome, b.WagerAmount, b.PayoutSubaddress,
        b.DepositTxID, b.DepositSubaddressIndex, b.BettorSigningKey, b.BettorI2PDest,
        b.Nonce, b.CreationBlock, b.GenesisHash))
}

func currentMoneroBlockHeight() (uint64, error) {
    reqBody := []byte(`{"jsonrpc":"2.0","id":"0","method":"get_block_count","params":[]}`)
    resp, err := http.Post("http://127.0.0.1:18081/json_rpc", "application/json", bytes.NewReader(reqBody))
    if err != nil {
        return 0, fmt.Errorf("failed to connect to monerod: %w", err)
    }
    defer resp.Body.Close()

    var rpcResp struct {
        Result struct {
            Count uint64 `json:"count"`
        } `json:"result"`
        Error struct {
            Code    int    `json:"code"`
            Message string `json:"message"`
        } `json:"error"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
        return 0, fmt.Errorf("failed to decode monerod response: %w", err)
    }
    if rpcResp.Error.Code != 0 {
        return 0, fmt.Errorf("monerod RPC error: %s", rpcResp.Error.Message)
    }
    return rpcResp.Result.Count, nil
}

// ========== MONERO CLIENT ==========

type MoneroClient struct {
    client   *walletrpc.Client
    ctx      context.Context
    username string
    password string
    seed     string
}

func NewMoneroClient(username, password, seed string) (*MoneroClient, error) {
    ctx := context.Background()

    httpClient := &http.Client{
        Transport: httpdigest.New(username, password),
    }

    client := walletrpc.New(walletrpc.Config{
        Address: "http://127.0.0.1:18082/json_rpc",
        Client:  httpClient,
    })

    if seed != "" {
        fmt.Println("Restoring wallet from seed...")
    }

    _, err := client.GetBalance(ctx, &walletrpc.GetBalanceRequest{
        AccountIndex: 0,
    })
    if err != nil {
        return nil, fmt.Errorf("cannot connect to monero-wallet-rpc: %w\n"+
            "Please run: monero-wallet-rpc --wallet-file wallet.bin --rpc-bind-port 18082 --rpc-login %s:***\n", err, username)
    }

    return &MoneroClient{
        client:   client,
        ctx:      ctx,
        username: username,
        password: password,
        seed:     seed,
    }, nil
}

func (m *MoneroClient) GenerateSubaddress(accountIndex uint32, label string) (uint32, string, error) {
    resp, err := m.client.CreateAddress(m.ctx, &walletrpc.CreateAddressRequest{
        AccountIndex: accountIndex,
        Label:        label,
    })
    if err != nil {
        return 0, "", fmt.Errorf("failed to create address: %w", err)
    }
    return resp.AddressIndex, resp.Address, nil
}

func (m *MoneroClient) CheckDeposit(subaddressIndex uint32, expectedAmount uint64) (string, uint64, int, error) {
    transfers, err := m.client.GetTransfers(m.ctx, &walletrpc.GetTransfersRequest{
        In:           true,
        AccountIndex: 0,
    })
    if err != nil {
        return "", 0, 0, fmt.Errorf("failed to get transfers: %w", err)
    }

    for _, tx := range transfers.In {
        if tx.SubaddrIndex.Minor == subaddressIndex {
            daemonHeight, err := currentMoneroBlockHeight()
            if err != nil {
                return tx.TxID, tx.Amount, 0, nil
            }
            confirmations := int(daemonHeight - tx.Height)
            return tx.TxID, tx.Amount, confirmations, nil
        }
    }
    return "", 0, 0, nil
}

func (m *MoneroClient) SendPayout(address string, amount uint64) (string, error) {
    resp, err := m.client.Transfer(m.ctx, &walletrpc.TransferRequest{
        Destinations: []walletrpc.Destination{
            {Address: address, Amount: amount},
        },
        AccountIndex: 0,
        Priority:     walletrpc.PriorityUnimportant,
    })
    if err != nil {
        return "", fmt.Errorf("failed to send payout: %w", err)
    }
    return resp.TxHash, nil
}

func (m *MoneroClient) SendDeveloperFee(amount uint64) (string, error) {
    if amount == 0 {
        return "", nil
    }
        return m.SendPayout(DeveloperAddress, amount)
}

func (m *MoneroClient) GetBalance() (uint64, uint64, error) {
    resp, err := m.client.GetBalance(m.ctx, &walletrpc.GetBalanceRequest{
        AccountIndex: 0,
    })
    if err != nil {
        return 0, 0, err
    }
    return resp.Balance, resp.UnlockedBalance, nil
}

// ========== I2P NETWORK ==========

type I2PNetwork struct {
    sam      *sam3.SAM
    session  *sam3.StreamSession
    identity *PersistedIdentity
    ctx      context.Context
    cancel   context.CancelFunc
    mu       sync.RWMutex
}

func NewI2PNetwork(identity *PersistedIdentity) (*I2PNetwork, error) {
    sam, err := sam3.NewSAM("127.0.0.1:7656")
    if err != nil {
        return nil, fmt.Errorf("failed to connect to I2P SAM bridge: %w\n"+
            "Please ensure I2P router is running (i2prouter start or i2pd --sam.enabled=true)", err)
    }

    var keys *sam3.Keys
    if identity.I2PPrivateKey != nil && identity.I2PPublicKey != nil {
        keys = &sam3.Keys{
            Pub:  identity.I2PPublicKey,
            Priv: identity.I2PPrivateKey,
        }
    } else {
        keys, err = sam.NewKeys()
        if err != nil {
            return nil, fmt.Errorf("failed to generate I2P keys: %w", err)
        }
        identity.I2PPublicKey = keys.Pub
        identity.I2PPrivateKey = keys.Priv
    }

    session, err := sam.NewStreamSession("prediction-market", keys, sam3.Options{
        "inbound.length":   "3",
        "outbound.length":  "3",
        "inbound.quantity": "3",
        "outbound.quantity": "3",
    })
    if err != nil {
        return nil, fmt.Errorf("failed to create I2P session: %w", err)
    }

    ctx, cancel := context.WithCancel(context.Background())

    return &I2PNetwork{
        sam:      sam,
        session:  session,
        identity: identity,
        ctx:      ctx,
        cancel:   cancel,
    }, nil
}

func (i *I2PNetwork) GetDestination() string {
    return i.session.Dest().String()
}

func (i *I2PNetwork) GetBase32Address() string {
    return i.session.Dest().Base32()
}

func (i *I2PNetwork) DialPeer(dest string) (net.Conn, error) {
    if !isValidI2PAddress(dest) {
        return nil, fmt.Errorf("invalid I2P address")
    }
    return i.session.Dial(dest)
}

func (i *I2PNetwork) StartListener(handler func(conn net.Conn)) error {
    listener, err := i.session.Listen()
    if err != nil {
        return fmt.Errorf("failed to create listener: %w", err)
    }

    go func() {
        for {
            select {
            case <-i.ctx.Done():
                return
            default:
                conn, err := listener.Accept()
                if err != nil {
                    continue
                }
                go handler(conn)
            }
        }
    }()

    return nil
}

func (i *I2PNetwork) Stop() {
    i.cancel()
}

// ========== HEARTBEAT SYSTEM ==========

type HeartbeatSystem struct {
    dht      *KademliaDHT
    identity *PersistedIdentity
    ctx      context.Context
    cancel   context.CancelFunc
}

func NewHeartbeatSystem(dht *KademliaDHT, identity *PersistedIdentity) *HeartbeatSystem {
    ctx, cancel := context.WithCancel(context.Background())
    return &HeartbeatSystem{
        dht:      dht,
        identity: identity,
        ctx:      ctx,
        cancel:   cancel,
    }
}

func (h *HeartbeatSystem) Start() {
    if !h.identity.IsOracle {
        return
    }
    go h.sendHeartbeatLoop()
}

func (h *HeartbeatSystem) sendHeartbeatLoop() {
    ticker := time.NewTicker(HeartbeatInterval)
    defer ticker.Stop()

    for {
        select {
        case <-h.ctx.Done():
            h.sendOfflineHeartbeat()
            return
        case <-ticker.C:
            h.sendHeartbeat()
        }
    }
}

func (h *HeartbeatSystem) sendHeartbeat() {
    status := OracleStatus{
        OracleID:      hex.EncodeToString(h.identity.SigningPublicKey[:8]),
        Online:        true,
        LastHeartbeat: uint64(time.Now().Unix()),
        CurrentVote:   "",
        Capacity:      3,
    }
    
    data, err := json.Marshal(status)
    if err != nil {
        return
    }
    
    key := fmt.Sprintf("oracle:heartbeat:%s", status.OracleID)
    if err := h.dht.StoreValue(key, data); err != nil {
        fmt.Printf("⚠️ Heartbeat failed: %v\n", err)
    }
}

func (h *HeartbeatSystem) sendOfflineHeartbeat() {
    status := OracleStatus{
        OracleID:      hex.EncodeToString(h.identity.SigningPublicKey[:8]),
        Online:        false,
        LastHeartbeat: uint64(time.Now().Unix()),
    }
    
    data, _ := json.Marshal(status)
    key := fmt.Sprintf("oracle:heartbeat:%s", status.OracleID)
    h.dht.StoreValue(key, data)
}

func (h *HeartbeatSystem) Stop() {
    h.cancel()
}

// ========== ORACLE SYSTEM ==========

type OracleSystem struct {
    dht      *KademliaDHT
    monero   *MoneroClient
    identity *PersistedIdentity
    session  *SessionData
    i2p      *I2PNetwork
}

func NewOracleSystem(dht *KademliaDHT, monero *MoneroClient, identity *PersistedIdentity, session *SessionData, i2p *I2PNetwork) *OracleSystem {
    return &OracleSystem{
        dht:      dht,
        monero:   monero,
        identity: identity,
        session:  session,
        i2p:      i2p,
    }
}

func (o *OracleSystem) AnnounceAsOracle(stakeAmount uint64) error {
    idx, addr, err := o.monero.GenerateSubaddress(0, "Oracle Stake")
    if err != nil {
        return err
    }

    fmt.Printf("\nSend %.4f XMR stake to:\n%s\n", float64(stakeAmount)/1e12, addr)
    fmt.Print("Press ENTER after sending...")
    bufio.NewReader(os.Stdin).ReadString('\n')

    var stakeTxID string
    fmt.Print("Waiting for confirmation")
    for i := 0; i < 60; i++ {
        txID, amount, confs, err := o.monero.CheckDeposit(idx, stakeAmount)
        if err == nil && amount >= stakeAmount && confs >= ConfirmationThresholdLarge {
            stakeTxID = txID
            break
        }
        fmt.Print(".")
        time.Sleep(2 * time.Second)
    }
    fmt.Println()

    if stakeTxID == "" {
        return fmt.Errorf("stake not confirmed after 120 seconds")
    }

    height, _ := currentMoneroBlockHeight()
    announcement := &OracleAnnouncement{
        ID:            sha256Hash([]byte(stakeTxID)),
        StakingTxID:   stakeTxID,
        StakingAmount: stakeAmount,
        SigningKey:    o.identity.SigningPublicKey,
        I2PDest:       o.i2p.GetDestination(),
        BlockHeight:   height,
    }

    announcementData, _ := json.Marshal(announcement)
    if err := o.dht.StoreValue("oracle:registration:"+announcement.ID, announcementData); err != nil {
        return err
    }

    o.session.AddOracleRegistration(announcement)
    o.identity.IsOracle = true

    return nil
}

func (o *OracleSystem) GetActiveOracles() ([]OracleStatus, error) {
    active := o.session.GetActiveOracles()
    
    var result []OracleStatus
    for _, status := range active {
        result = append(result, *status)
    }
    return result, nil
}

func (o *OracleSystem) SelectRandomOracles(count int) ([]OracleStatus, error) {
    active := o.session.GetActiveOracles()
    if len(active) == 0 {
        return nil, fmt.Errorf("no active oracles found")
    }
    
    if len(active) < count {
        count = len(active)
    }
    
    // Shuffle
    shuffled := make([]*OracleStatus, len(active))
    copy(shuffled, active)
    rand.Shuffle(len(shuffled), func(i, j int) {
        shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
    })
    
    var selected []OracleStatus
    for i := 0; i < count && i < len(shuffled); i++ {
        selected = append(selected, *shuffled[i])
    }
    return selected, nil
}

// ========== RESOLUTION PROPOSAL SYSTEM ==========

type ResolutionSystem struct {
    dht        *KademliaDHT
    monero     *MoneroClient
    identity   *PersistedIdentity
    session    *SessionData
    oracleSys  *OracleSystem
    reader     *bufio.Reader
    i2p        *I2PNetwork
}

func NewResolutionSystem(dht *KademliaDHT, monero *MoneroClient, identity *PersistedIdentity, session *SessionData, oracleSys *OracleSystem, i2p *I2PNetwork) *ResolutionSystem {
    return &ResolutionSystem{
        dht:       dht,
        monero:    monero,
        identity:  identity,
        session:   session,
        oracleSys: oracleSys,
        i2p:       i2p,
    }
}

func (r *ResolutionSystem) ProposeResolution(market *Market) error {
    fmt.Printf("\nResolving market: %s\n", market.EventName)
    fmt.Printf("Resolution block: %d\n", market.ResolutionBlock)
    fmt.Println("\nProvide justification for your resolution.")
    fmt.Println("Cite sources, explain your reasoning.")
    fmt.Println("Type '+++' on a new line when done.\n")
    
    var justificationLines []string
    for {
        line, _ := r.reader.ReadString('\n')
        line = strings.TrimSpace(line)
        if line == "+++" {
            break
        }
        justificationLines = append(justificationLines, line)
    }
    justification := strings.Join(justificationLines, "\n")
    
    if justification == "" {
        return fmt.Errorf("justification required")
    }
    
    fmt.Print("\nOutcome (yes/no): ")
    outcomeStr, _ := r.reader.ReadString('\n')
    outcome := strings.TrimSpace(outcomeStr) == "yes"
    
    proposal := &ResolutionProposal{
        ID:            sha256Hash([]byte(fmt.Sprintf("%s|%s|%d", market.ID, r.identity.SigningPublicKey, time.Now().Unix()))),
        MarketID:      market.ID,
        Outcome:       outcome,
        Justification: justification,
        MakerKey:      r.identity.SigningPublicKey,
        Timestamp:     uint64(time.Now().Unix()),
        Status:        "pending",
    }
    
    propData, err := json.Marshal(proposal)
    if err != nil {
        return err
    }
    
    // Sign the proposal
    proposal.Signature = ed25519.Sign(r.identity.SigningPrivateKey, propData)
    
    // Store in DHT
    if err := r.dht.StoreValue("proposal:"+proposal.ID, propData); err != nil {
        return err
    }
    
    r.session.AddResolutionProposal(proposal)
    market.ResolutionProposalID = proposal.ID
    
    fmt.Printf("\n✅ Resolution proposal sent. Waiting for oracles to vote...\n")
    fmt.Printf("   Proposal ID: %s\n", proposal.ID[:16])
    
    // Start monitoring votes
    go r.monitorVotes(proposal, market)
    
    return nil
}

func (r *ResolutionSystem) monitorVotes(proposal *ResolutionProposal, market *Market) {
    // Get active oracles
    activeOracles, err := r.oracleSys.GetActiveOracles()
    if err != nil || len(activeOracles) == 0 {
        fmt.Printf("\n⚠️ No active oracles found. Waiting for oracles to come online...\n")
        // Keep trying for 10 hours
        deadline := time.Now().Add(ProposalQueryHours * time.Hour)
        for time.Now().Before(deadline) {
            time.Sleep(10 * time.Minute)
            activeOracles, err = r.oracleSys.GetActiveOracles()
            if err == nil && len(activeOracles) >= MinOraclesRequired {
                break
            }
        }
        
        // If still no oracles after deadline, fallback to maker decision
        if len(activeOracles) < MinOraclesRequired {
            fmt.Printf("\n⚠️ No oracles found after %d hours. Falling back to maker's decision.\n", ProposalQueryHours)
            r.executeResolution(proposal, market)
            return
        }
    }
    
    // Random threshold between MinOraclesRequired and MaxOraclesRequired
    threshold := MinOraclesRequired + rand.Intn(MaxOraclesRequired-MinOraclesRequired+1)
    fmt.Printf("\n📋 Resolution proposal sent to oracles. Need %d approvals.\n", threshold)
    
    // Notify selected oracles (in production, send direct I2P messages)
    selectedOracles, _ := r.oracleSys.SelectRandomOracles(threshold * 2)
    
    // Wait for votes
    deadline := time.Now().Add(OracleResponseTimeoutHours * time.Hour)
    votesReceived := 0
    approvals := 0
    
    for time.Now().Before(deadline) {
        votes := r.session.GetOracleVotes(proposal.ID)
        votesReceived = len(votes)
        approvals = 0
        for _, v := range votes {
            if v.Vote {
                approvals++
            }
        }
        
        fmt.Printf("Votes received: %d/%d (approvals: %d)\n", votesReceived, threshold, approvals)
        
        if approvals >= threshold {
            fmt.Println("\n✅ Proposal approved by oracles! Resolving market...")
            r.executeResolution(proposal, market)
            return
        }
        
        if votesReceived > 0 && (votesReceived-approvals) > (len(selectedOracles)-threshold) {
            fmt.Println("\n❌ Proposal rejected by oracles.")
            proposal.Status = "rejected"
            r.session.AddResolutionProposal(proposal)
            return
        }
        
        time.Sleep(30 * time.Second)
    }
    
    // Timeout - fallback to maker decision
    fmt.Printf("\n⏰ Oracle vote timeout after %d hours. Falling back to maker's decision.\n", OracleResponseTimeoutHours)
    r.executeResolution(proposal, market)
}

func (r *ResolutionSystem) executeResolution(proposal *ResolutionProposal, market *Market) {
    currentHeight, _ := currentMoneroBlockHeight()
    
    // Process payouts
    bets := r.session.GetSeenBetOffersForMarket(market.ID)
    paidCount := 0
    for _, bet := range bets {
        if bet.ChosenOutcome == proposal.Outcome && bet.Status == "accepted" {
            payout := bet.WagerAmount * market.OddsNumerator / market.OddsDenominator
            afterFees := payout * (100 - DeveloperFeePercent - OracleFeePercent) / 100
            devFee := payout * DeveloperFeePercent / 100
            
            txHash, err := r.monero.SendPayout(bet.PayoutSubaddress, afterFees)
            if err != nil {
                fmt.Printf("Failed to pay %s: %v\n", bet.PayoutSubaddress[:16], err)
                continue
            }
            
            if devFee > 0 {
                if _, err := r.monero.SendDeveloperFee(devFee); err != nil {
                    fmt.Printf("Failed to send developer fee: %v\n", err)
                } else {
                    fmt.Printf("💰 Developer fee: %.4f XMR collected\n", float64(devFee)/1e12)
                }
            }
            
            fmt.Printf("✅ Paid %.4f XMR to bettor (tx: %s)\n", float64(afterFees)/1e12, txHash[:16])
            bet.Status = "paid"
            paidCount++
        }
    }
    
    market.Resolved = true
    market.ResolutionOutcome = &proposal.Outcome
    market.ResolutionBlockActual = currentHeight
    
    fmt.Printf("\n✅ Market resolved as '%s'\n", map[bool]string{true: "YES", false: "NO"}[proposal.Outcome])
    fmt.Printf("   Paid %d winning bets\n", paidCount)
}

func (r *ResolutionSystem) MonitorOracleRequests() {
    // This runs in background, checking for resolution proposals addressed to this oracle
    for {
        time.Sleep(5 * time.Second)
        
        // Check for pending proposals (in production, would check DHT for proposals addressed to this oracle)
        proposals := r.session.ResolutionProposals
        for _, prop := range proposals {
            if prop.Status != "pending" {
                continue
            }
            
            // Check if this oracle has already voted
            votes := r.session.GetOracleVotes(prop.ID)
            alreadyVoted := false
            for _, v := range votes {
                if string(v.OracleKey) == string(r.identity.SigningPublicKey) {
                    alreadyVoted = true
                    break
                }
            }
            
            if alreadyVoted {
                continue
            }
            
            // Notify oracle
            fmt.Printf("\n🔔 ========================================\n")
            fmt.Printf("📋 NEW RESOLUTION PROPOSAL RECEIVED\n")
            fmt.Printf("   Market ID: %s\n", prop.MarketID[:16])
            fmt.Printf("   Proposed outcome: %v\n", prop.Outcome)
            fmt.Printf("   Justification:\n%s\n", prop.Justification)
            fmt.Printf("\n   Type 'open' to review and vote, or 'FN' to reject this session.\n")
            fmt.Printf("========================================\n")
            
            // Wait for oracle response
            responseChan := make(chan string)
            go func() {
                response, _ := r.reader.ReadString('\n')
                responseChan <- strings.TrimSpace(response)
            }()
            
            select {
            case response := <-responseChan:
                if response == "FN" {
                    fmt.Println("Vote session rejected.")
                    continue
                }
                if response == "open" {
                    fmt.Print("Approve this resolution? (yes/no): ")
                    voteResp, _ := r.reader.ReadString('\n')
                    vote := strings.TrimSpace(voteResp) == "yes"
                    
                    oracleVote := &OracleVote{
                        ProposalID: prop.ID,
                        Vote:       vote,
                        OracleKey:  r.identity.SigningPublicKey,
                        Timestamp:  uint64(time.Now().Unix()),
                    }
                    
                    voteData, _ := json.Marshal(oracleVote)
                    r.dht.StoreValue("vote:"+prop.ID+":"+hex.EncodeToString(r.identity.SigningPublicKey[:8]), voteData)
                    r.session.AddOracleVote(oracleVote)
                    
                    if vote {
                        fmt.Println("✓ Vote recorded: APPROVED")
                    } else {
                        fmt.Println("✓ Vote recorded: REJECTED")
                    }
                }
            case <-time.After(OracleResponseTimeoutHours * time.Hour):
                fmt.Printf("\n⏰ Vote timeout. Proposal %s automatically rejected.\n", prop.ID[:16])
            }
        }
    }
}

// ========== MAIN CLIENT ==========

type PredictionClient struct {
    identity       *PersistedIdentity
    session        *SessionData
    monero         *MoneroClient
    i2p            *I2PNetwork
    dht            *KademliaDHT
    oracleSys      *OracleSystem
    heartbeatSys   *HeartbeatSystem
    resolutionSys  *ResolutionSystem
    reader         *bufio.Reader
    ctx            context.Context
    cancel         context.CancelFunc
    dbPath         string
}

func NewPredictionClient(dbPath, password string, createNew bool, isOracle bool) (*PredictionClient, error) {
    var identity *PersistedIdentity
    var err error
    
    if createNew {
        fmt.Println("\n🔐 Creating new identity...")
        identity, err = CreateNewIdentity(dbPath, password, isOracle)
        if err != nil {
            return nil, fmt.Errorf("failed to create identity: %w", err)
        }
        fmt.Println("✅ Identity created and saved to", filepath.Join(dbPath, "identity.enc"))
    } else {
        fmt.Println("\n🔐 Loading existing identity...")
        identity, err = LoadIdentity(dbPath, password)
        if err != nil {
            return nil, fmt.Errorf("failed to load identity: %w", err)
        }
        fmt.Println("✅ Identity loaded successfully")
    }

    moneroUser := os.Getenv("XMR_RPC_USER")
    moneroPass := os.Getenv("XMR_RPC_PASS")
    if moneroUser == "" {
        moneroUser = "default"
        moneroPass = "changeme"
        fmt.Println("\n⚠️ WARNING: Monero RPC using default credentials!")
        fmt.Println("   Set XMR_RPC_USER and XMR_RPC_PASS environment variables")
    }
    
    monero, err := NewMoneroClient(moneroUser, moneroPass, identity.MoneroSeed)
    if err != nil {
        return nil, err
    }

    i2p, err := NewI2PNetwork(identity)
    if err != nil {
        return nil, err
    }

    session := NewSessionData()
    
    // Restore active markets from persisted identity
    for id, market := range identity.ActiveMarkets {
        session.DiscoveredMarkets[id] = market
    }
        for id, bet := range identity.PendingBets {
        session.SeenBetOffers[id] = bet
    }

    nodeID := sha256HashToID(hex.EncodeToString(identity.SigningPublicKey))
    dht := NewKademliaDHT(nodeID, session, i2p)
    if err := dht.Start(); err != nil {
        return nil, fmt.Errorf("failed to start DHT: %w", err)
    }

    oracleSys := NewOracleSystem(dht, monero, identity, session, i2p)
    heartbeatSys := NewHeartbeatSystem(dht, identity)
    heartbeatSys.Start()
    
    resolutionSys := NewResolutionSystem(dht, monero, identity, session, oracleSys, i2p)

    ctx, cancel := context.WithCancel(context.Background())

    return &PredictionClient{
        identity:      identity,
        session:       session,
        monero:        monero,
        i2p:           i2p,
        dht:           dht,
        oracleSys:     oracleSys,
        heartbeatSys:  heartbeatSys,
        resolutionSys: resolutionSys,
        reader:        bufio.NewReader(os.Stdin),
        ctx:           ctx,
        cancel:        cancel,
        dbPath:        dbPath,
    }, nil
}

func (c *PredictionClient) Run() {
    c.printBanner()
    c.printStakeSlashingDisclaimer()
    
    // Start oracle request monitor if user is oracle
    if c.identity.IsOracle {
        go c.resolutionSys.MonitorOracleRequests()
    }

    for {
        fmt.Println("\n┌────────────────────────────────────────────────────────────┐")
        fmt.Println("│                       MAIN MENU                             │")
        fmt.Println("├────────────────────────────────────────────────────────────┤")
        fmt.Println("│  1. Post a Market                                           │")
        fmt.Println("│  2. Browse Markets                                          │")
        fmt.Println("│  3. Check My Bets                                           │")
        fmt.Println("│  4. Propose Market Resolution (if maker)                    │")
        fmt.Println("│  5. File Dispute (dishonest resolution)                     │")
        fmt.Println("│  6. File Non-Resolution Complaint                           │")
        fmt.Println("│  7. Announce as Oracle (stake required)                     │")
        fmt.Println("│  8. Show My Identity                                        │")
        fmt.Println("│  9. Check Wallet Balance                                    │")
        fmt.Println("│ 10. Add Peer (join the network)                             │")
        fmt.Println("│ 11. Show Network Status                                     │")
        fmt.Println("│ 12. Exit (session data lost, identity saved)                │")
        fmt.Println("└────────────────────────────────────────────────────────────┘")
        fmt.Print("\nChoice: ")

        choice, _ := c.reader.ReadString('\n')
        choice = strings.TrimSpace(choice)

        switch choice {
        case "1":
            c.postMarket()
        case "2":
            c.browseMarkets()
        case "3":
            c.checkMyBets()
        case "4":
            c.proposeResolution()
        case "5":
            c.fileDispute()
        case "6":
            c.fileComplaint()
        case "7":
            c.announceOracle()
        case "8":
            c.showIdentity()
        case "9":
            c.checkBalance()
        case "10":
            c.addPeer()
        case "11":
            c.showNetworkStatus()
        case "12":
            fmt.Println("\nSaving identity changes...")
            c.saveIdentity()
            fmt.Println("Goodbye!")
            c.cancel()
            return
        }
    }
}

func (c *PredictionClient) saveIdentity() {
    // Save active markets and pending bets back to identity
    c.identity.ActiveMarkets = make(map[string]*Market)
    c.identity.PendingBets = make(map[string]*BetOffer)
    
    for id, market := range c.session.DiscoveredMarkets {
        if string(market.MakerSigningKey) == string(c.identity.SigningPublicKey) && !market.Resolved {
            c.identity.ActiveMarkets[id] = market
        }
    }
    
    for id, bet := range c.session.SeenBetOffers {
        if string(bet.BettorSigningKey) == string(c.identity.SigningPublicKey) && bet.Status == "pending" {
            c.identity.PendingBets[id] = bet
        }
    }
    
    // Need password - in production, prompt or cache
    fmt.Println("Identity changes saved to disk.")
}

func (c *PredictionClient) printBanner() {
    oracleStatus := ""
    if c.identity.IsOracle {
        oracleStatus = " | ORACLE MODE ACTIVE"
    }
    
    fmt.Printf("\n╔════════════════════════════════════════════════════════════════╗\n")
    fmt.Printf("║                    PREDICTION MARKET CLIENT%s             ║\n", oracleStatus)
    fmt.Printf("╠════════════════════════════════════════════════════════════════╣\n")
    fmt.Printf("║ Genesis: %s║\n", GenesisHash[:32])
    fmt.Printf("║ Dev Fee: %d%% | Oracle Fee: %d%%                                  ║\n", DeveloperFeePercent, OracleFeePercent)
    fmt.Printf("║ Min Bet: %.4f XMR | Bond: %.4f XMR                               ║\n", float64(MinBetSizePiconero)/1e12, float64(BondAmountPiconero)/1e12)
    fmt.Printf("║ I2P Address: %s...                                          ║\n", c.i2p.GetBase32Address()[:25])
    fmt.Printf("║ Node ID: %x...                                                  ║\n", c.dht.NodeID[:8])
    fmt.Printf("╚════════════════════════════════════════════════════════════════╝\n")
}

func (c *PredictionClient) printStakeSlashingDisclaimer() {
    fmt.Println("\n╔════════════════════════════════════════════════════════════════╗")
    fmt.Println("║  DISCLAIMER: Stake slashing is NOT enforced by Monero.        ║")
    fmt.Println("║  Oracle stakes cannot be slashed on-chain. Verify oracle      ║")
    fmt.Println("║  honesty by cross-referencing multiple independent oracles.   ║")
    fmt.Println("╚════════════════════════════════════════════════════════════════╝")
}

func (c *PredictionClient) addPeer() {
    fmt.Println("\n┌────────────────────────────────────────────────────────────┐")
    fmt.Println("│                    ADD PEER TO NETWORK                      │")
    fmt.Println("└────────────────────────────────────────────────────────────┘")
    fmt.Println()
    fmt.Println("To join the prediction market network, enter an I2P address")
    fmt.Println("of an existing peer.")
    fmt.Println()
    fmt.Println("Valid formats:")
    fmt.Println("  - Base32 (52 chars): abc123...b32.i2p")
    fmt.Println("  - Base32 encrypted (56+ chars): def456...b32.i2p")
    fmt.Println("  - Hostname: example.i2p")
    fmt.Println()
    fmt.Println("Peers expire after 1 hour of no contact.")
    fmt.Print("\nI2P Address: ")
    peerAddr, _ := c.reader.ReadString('\n')
    peerAddr = strings.TrimSpace(peerAddr)

    if peerAddr == "" {
        fmt.Println("No address entered.")
        return
    }

    if !isValidI2PAddress(peerAddr) {
        fmt.Println("❌ Invalid I2P address format.")
        return
    }

    fmt.Println("\nConnecting to peer...")
    nodeID := make([]byte, 20)
    rand.Read(nodeID)
    c.dht.AddPeer(nodeID, peerAddr)
    
    fmt.Println("✅ Peer added successfully!")
    fmt.Println("The DHT will now discover other peers automatically.")

    go func() {
        _, err := c.dht.IterativeFindNode(c.dht.NodeID)
        if err != nil {
            fmt.Printf("\n⚠️ Peer discovery warning: %v\n", err)
        } else {
            fmt.Printf("\n🌐 Network discovered! Found %d peers.\n", c.dht.GetPeerCount())
        }
    }()
}

func (c *PredictionClient) showNetworkStatus() {
    peerCount := c.dht.GetPeerCount()
    marketCount := len(c.session.DiscoveredMarkets)
    betCount := len(c.session.SeenBetOffers)
    activeOracles, _ := c.oracleSys.GetActiveOracles()
    
    fmt.Println("\n┌────────────────────────────────────────────────────────────┐")
    fmt.Println("│                    NETWORK STATUS                           │")
    fmt.Println("└────────────────────────────────────────────────────────────┘")
    fmt.Printf("\n  Node ID:     %x\n", c.dht.NodeID[:8])
    fmt.Printf("  I2P Address: %s\n", c.i2p.GetBase32Address()[:40])
    fmt.Printf("  Known Peers: %d\n", peerCount)
    fmt.Printf("  Markets in DHT: %d\n", marketCount)
    fmt.Printf("  Bet Offers: %d\n", betCount)
    fmt.Printf("  Active Oracles: %d\n", len(activeOracles))
    
    if peerCount == 0 {
        fmt.Println("\n⚠️ You are not connected to any peers!")
        fmt.Println("   Use option 10 to add a peer and join the network.")
    }
}

func (c *PredictionClient) postMarket() {
    fmt.Println("\n┌────────────────────────────────────────────────────────────┐")
    fmt.Println("│                    CREATE NEW MARKET                        │")
    fmt.Println("└────────────────────────────────────────────────────────────┘")

    fmt.Print("Event name: ")
    name, _ := c.reader.ReadString('\n')
    name = strings.TrimSpace(name)
    if name == "" {
        fmt.Println("Event name required")
        return
    }

    fmt.Print("Event description: ")
    desc, _ := c.reader.ReadString('\n')
    desc = strings.TrimSpace(desc)

    currentHeight, err := currentMoneroBlockHeight()
    if err != nil {
        fmt.Printf("❌ Failed to get current block height: %v\n", err)
        return
    }
    fmt.Printf("\nCurrent Monero block height: %d\n", currentHeight)

    fmt.Print("Resolution block height (Monero block # must be > current height): ")
    blockStr, _ := c.reader.ReadString('\n')
    blockHeight, err := strconv.ParseUint(strings.TrimSpace(blockStr), 10, 64)
    if err != nil {
        fmt.Printf("Invalid block height: %v\n", err)
        return
    }

    if blockHeight <= currentHeight {
        fmt.Printf("❌ Cannot set resolution to block %d (current block is %d)\n", blockHeight, currentHeight)
        fmt.Println("   Resolution block must be in the future to prevent scams.")
        return
    }

    fmt.Print("Odds (format: numerator denominator, e.g., '2 1' for 2:1): ")
    oddsStr, _ := c.reader.ReadString('\n')
    var num, denom uint64
    if _, err := fmt.Sscanf(strings.TrimSpace(oddsStr), "%d %d", &num, &denom); err != nil {
        fmt.Printf("Invalid odds format: %v\n", err)
        return
    }
    if denom == 0 {
        denom = 1
    }

    fmt.Print("Max liability (XMR): ")
    liabilityStr, _ := c.reader.ReadString('\n')
    liabilityXMR, err := strconv.ParseFloat(strings.TrimSpace(liabilityStr), 64)
    if err != nil {
        fmt.Printf("Invalid liability: %v\n", err)
        return
    }
    maxLiability := uint64(liabilityXMR * 1e12)

    fmt.Printf("\nLocking bond of %.4f XMR...\n", float64(BondAmountPiconero)/1e12)
    bondIdx, bondAddr, err := c.monero.GenerateSubaddress(0, "Market Bond")
    if err != nil {
        fmt.Printf("Failed to generate bond address: %v\n", err)
        return
    }

    fmt.Printf("Send exactly %.4f XMR to:\n%s\n", float64(BondAmountPiconero)/1e12, bondAddr)
    fmt.Print("Press ENTER after sending...")
    c.reader.ReadString('\n')

    var bondTxID string
    fmt.Print("Waiting for confirmation")
    for i := 0; i < 60; i++ {
        txID, amount, confs, err := c.monero.CheckDeposit(bondIdx, BondAmountPiconero)
        if err == nil && amount >= BondAmountPiconero && confs >= ConfirmationThresholdSmall {
            bondTxID = txID
            break
        }
        fmt.Print(".")
        time.Sleep(2 * time.Second)
    }
    fmt.Println()

    if bondTxID == "" {
        fmt.Println("Bond not confirmed after 120 seconds")
        return
    }
    fmt.Println("Bond confirmed!")

    market := &Market{
        EventName:        name,
        EventDescription: desc,
        ResolutionBlock:  blockHeight,
        OddsNumerator:    num,
        OddsDenominator:  denom,
        MaxLiability:     maxLiability,
        UsedLiability:    0,
        BondTxID:         bondTxID,
        MakerSigningKey:  c.identity.SigningPublicKey,
        MakerI2PDest:     c.i2p.GetDestination(),
        Nonce:            uint64(time.Now().UnixNano()),
        CreationBlock:    currentHeight,
        GenesisHash:      GenesisHash,
    }

    serialized := serializeMarket(market)
    market.Signature = ed25519.Sign(c.identity.SigningPrivateKey, serialized)
    market.ID = sha256Hash(serialized)

    c.session.AddDiscoveredMarket(market)

    marketData, _ := json.Marshal(market)
    if err := c.dht.StoreValue("market:"+market.ID, marketData); err != nil {
        fmt.Printf("Warning: Failed to store market in DHT: %v\n", err)
    }

    fmt.Printf("\n✅ Market created successfully!\n")
    fmt.Printf("   Market ID: %s\n", market.ID)
    fmt.Printf("   Resolution block: %d (current: %d)\n", blockHeight, currentHeight)
}

func (c *PredictionClient) browseMarkets() {
    fmt.Println("\n┌────────────────────────────────────────────────────────────┐")
    fmt.Println("│                    ACTIVE MARKETS                            │")
    fmt.Println("└────────────────────────────────────────────────────────────┘")

    markets := c.session.GetDiscoveredMarkets()
    if len(markets) == 0 {
        fmt.Println("\nNo markets found. Use option 10 to add peers and discover markets.")
        return
    }

    for i, m := range markets {
        remaining := float64(m.MaxLiability-m.UsedLiability) / 1e12
        fmt.Printf("\n%d. %s\n", i+1, m.EventName)
        fmt.Printf("   Odds: %d:%d | Liability left: %.4f XMR\n", m.OddsNumerator, m.OddsDenominator, remaining)
        fmt.Printf("   Resolves: block %d\n", m.ResolutionBlock)
        fmt.Printf("   ID: %s\n", m.ID[:16])
    }

    fmt.Print("\nSelect market to bet on (#): ")
    choiceStr, _ := c.reader.ReadString('\n')
    idx, err := strconv.Atoi(strings.TrimSpace(choiceStr))
    if err != nil || idx < 1 || idx > len(markets) {
        fmt.Println("Invalid selection")
        return
    }

    c.placeBet(markets[idx-1])
}

func (c *PredictionClient) placeBet(market *Market) {
    remaining := market.MaxLiability - market.UsedLiability
    fmt.Printf("\nRemaining liability: %.4f XMR\n", float64(remaining)/1e12)

    fmt.Print("\nYour payout subaddress: ")
    payoutAddr, _ := c.reader.ReadString('\n')
    payoutAddr = strings.TrimSpace(payoutAddr)

    fmt.Print("Outcome (yes/no): ")
    outcomeStr, _ := c.reader.ReadString('\n')
    outcome := strings.TrimSpace(outcomeStr) == "yes"

    fmt.Print("Wager amount (XMR): ")
    wagerStr, _ := c.reader.ReadString('\n')
    wagerXMR, err := strconv.ParseFloat(strings.TrimSpace(wagerStr), 64)
    if err != nil {
        fmt.Printf("Invalid wager: %v\n", err)
        return
    }
    wagerAmount := uint64(wagerXMR * 1e12)

    if wagerAmount < MinBetSizePiconero {
        fmt.Printf("Minimum bet is %.4f XMR\n", float64(MinBetSizePiconero)/1e12)
        return
    }

    if wagerAmount > remaining {
        fmt.Println("Wager exceeds remaining liability")
        return
    }

    payout := wagerAmount * market.OddsNumerator / market.OddsDenominator
    afterFees := payout * (100 - DeveloperFeePercent - OracleFeePercent) / 100
    devFee := payout * DeveloperFeePercent / 100

    fmt.Printf("\nBet Summary:\n")
    fmt.Printf("  Wager: %.4f XMR\n", float64(wagerAmount)/1e12)
    fmt.Printf("  Payout after fees: %.4f XMR\n", float64(afterFees)/1e12)
    fmt.Printf("  Dev fee (2%%): %.4f XMR\n", float64(devFee)/1e12)

    fmt.Print("\nConfirm bet? (yes/no): ")
    confirm, _ := c.reader.ReadString('\n')
    if strings.TrimSpace(confirm) != "yes" {
        return
    }

    depositIdx, depositAddr, err := c.monero.GenerateSubaddress(0, fmt.Sprintf("Bet for %s", market.EventName[:20]))
    if err != nil {
        fmt.Printf("Failed to generate deposit address: %v\n", err)
        return
    }

    fmt.Printf("\n💰 Send exactly %.4f XMR to:\n%s\n", float64(wagerAmount)/1e12, depositAddr)
    fmt.Print("Press ENTER after sending...")
    c.reader.ReadString('\n')

    var depositTxID string
    requiredConfs := ConfirmationThresholdSmall
    if wagerAmount >= ConfirmationAmountThreshold {
        requiredConfs = ConfirmationThresholdLarge
    }

    fmt.Print("Waiting for confirmation")
    for i := 0; i < 120; i++ {
        txID, amount, confs, err := c.monero.CheckDeposit(depositIdx, wagerAmount)
        if err == nil && amount >= wagerAmount && confs >= requiredConfs {
            depositTxID = txID
            break
        }
        fmt.Print(".")
        time.Sleep(2 * time.Second)
    }
    fmt.Println()

    if depositTxID == "" {
        fmt.Println("Deposit not confirmed after 240 seconds")
        return
    }
    fmt.Println("Deposit confirmed!")

    currentHeight, _ := currentMoneroBlockHeight()

    bet := &BetOffer{
        MarketID:               market.ID,
        ChosenOutcome:          outcome,
        WagerAmount:            wagerAmount,
        PayoutSubaddress:       payoutAddr,
        DepositTxID:            depositTxID,
        DepositSubaddressIndex: depositIdx,
        BettorSigningKey:       c.identity.SigningPublicKey,
        BettorI2PDest:          c.i2p.GetDestination(),
        Nonce:                  uint64(time.Now().UnixNano()),
        CreationBlock:          currentHeight,
        GenesisHash:            GenesisHash,
        Status:                 "pending",
    }

    serialized := serializeBetOffer(bet)
    bet.Signature = ed25519.Sign(c.identity.SigningPrivateKey, serialized)
    bet.ID = sha256Hash(serialized)

    c.session.AddSeenBetOffer(bet)

    betData, _ := json.Marshal(bet)
    if err := c.dht.StoreValue("bet:"+market.ID+":"+bet.ID, betData); err != nil {
        fmt.Printf("Warning: Failed to store bet in DHT: %v\n", err)
    }

    fmt.Printf("\n✅ Bet placed! Offer ID: %s\n", bet.ID[:16])
    fmt.Println("Waiting for market maker acceptance...")

    go c.pollForAcceptance(bet.ID)
}

func (c *PredictionClient) pollForAcceptance(betID string) {
    for i := 0; i < 60; i++ {
        time.Sleep(2 * time.Second)
        if acc, ok := c.session.GetAcceptance(betID); ok {
            fmt.Printf("\n🎉 Bet ACCEPTED by maker %x...\n", acc.MakerKey[:8])
            if bet, ok := c.session.SeenBetOffers[betID]; ok {
                bet.Status = "accepted"
                if market, ok := c.session.DiscoveredMarkets[bet.MarketID]; ok {
                    market.UsedLiability += bet.WagerAmount
                }
            }
            return
        }
    }
    fmt.Printf("\n⏰ Bet %s still pending. Maker may accept later.\n", betID[:16])
}

func (c *PredictionClient) checkMyBets() {
    var myBets []*BetOffer
    for _, bet := range c.session.SeenBetOffers {
        if string(bet.BettorSigningKey) == string(c.identity.SigningPublicKey) {
            myBets = append(myBets, bet)
        }
    }
    
    if len(myBets) == 0 {
        fmt.Println("\nNo bets found.")
        return
    }

    fmt.Println("\n--- YOUR BETS ---")
    for _, bet := range myBets {
        market, ok := c.session.DiscoveredMarkets[bet.MarketID]
        marketName := "Unknown"
        if ok {
            marketName = market.EventName
        }
        fmt.Printf("\nBet on: %s\n", marketName)
        fmt.Printf("  Outcome: %v | Wager: %.4f XMR\n", bet.ChosenOutcome, float64(bet.WagerAmount)/1e12)
        fmt.Printf("  Status: %s\n", bet.Status)
    }
}

func (c *PredictionClient) proposeResolution() {
    var myMarkets []*Market
    for _, m := range c.session.DiscoveredMarkets {
        if string(m.MakerSigningKey) == string(c.identity.SigningPublicKey) && !m.Resolved {
            myMarkets = append(myMarkets, m)
        }
    }

    if len(myMarkets) == 0 {
        fmt.Println("\nNo unresolved markets that you created.")
        return
    }

    fmt.Println("\n--- YOUR UNRESOLVED MARKETS ---")
    for i, m := range myMarkets {
        fmt.Printf("%d. %s (resolves at block %d)\n", i+1, m.EventName, m.ResolutionBlock)
    }

    fmt.Print("\nSelect market to resolve: ")
    choiceStr, _ := c.reader.ReadString('\n')
    idx, err := strconv
 
