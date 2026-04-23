go
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
    OracleResponseTimeoutHours = 24
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

type Resolution struct {
    MarketID    string `json:"market_id"`
    Outcome     bool   `json:"outcome"`
    BlockHeight uint64 `json:"block_height"`
    MakerKey    []byte `json:"maker_key"`
    Signature   []byte `json:"signature"`
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

type OracleAnnouncement struct {
    ID            string `json:"id"`
    StakingTxID   string `json:"staking_txid"`
    StakingAmount uint64 `json:"staking_amount"`
    SigningKey    []byte `json:"signing_key"`
    I2PDest       string `json:"i2p_dest"`
    BlockHeight   uint64 `json:"block_height"`
    Signature     []byte `json:"signature"`
}

type PeerNode struct {
    ID          []byte
    I2PDest     string
    LastSeen    time.Time
    Successes   int
    Failures    int
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

type KademliaDHT struct {
    NodeID        []byte
    RoutingTable  [NodeIDBits]*KBucket
    Store         map[string]StoredData
    StoreMu       sync.RWMutex
    I2P           *I2PNetwork
    ctx           context.Context
    cancel        context.CancelFunc
    rateLimiter   *RateLimiter
    mu            sync.RWMutex
}

type StoredData struct {
    Value     []byte
    Timestamp time.Time
    TTL       time.Duration
}

func NewKademliaDHT(i2p *I2PNetwork) *KademliaDHT {
    ctx, cancel := context.WithCancel(context.Background())

    nodeID := make([]byte, 20)
    rand.Read(nodeID)

    dht := &KademliaDHT{
        NodeID:       nodeID,
        Store:        make(map[string]StoredData),
        I2P:          i2p,
        ctx:          ctx,
        cancel:       cancel,
        rateLimiter:  NewRateLimiter(RateLimitInterval, RateLimitMaxQueries),
    }

    for i := 0; i < NodeIDBits; i++ {
        dht.RoutingTable[i] = NewKBucket(KademliaBucketSize)
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
    go d.republishLoop()
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
    d.RoutingTable[bucketIdx].Add(node)
}

func (d *KademliaDHT) AddManualPeer(i2pDest string) error {
    if !isValidI2PAddress(i2pDest) {
        return fmt.Errorf("invalid I2P address format")
    }
    
    msg := struct {
        Type      string `json:"type"`
        SenderID  []byte `json:"sender_id"`
        SenderDest string `json:"sender_dest"`
    }{
        Type:      "PING",
        SenderID:  d.NodeID,
        SenderDest: d.I2P.GetDestination(),
    }

    var response struct {
        Type      string `json:"type"`
        ResponderID []byte `json:"responder_id"`
    }

    conn, err := d.I2P.DialPeer(i2pDest)
    if err != nil {
        return fmt.Errorf("failed to dial peer: %w", err)
    }
    defer conn.Close()

    if err := json.NewEncoder(conn).Encode(msg); err != nil {
        return fmt.Errorf("failed to send ping: %w", err)
    }

    if err := json.NewDecoder(conn).Decode(&response); err != nil {
        return fmt.Errorf("failed to read ping response: %w", err)
    }

    d.AddPeer(response.ResponderID, i2pDest)
    return nil
}

func (d *KademliaDHT) FindClosest(target []byte, count int) []*PeerNode {
    bucketIdx := d.getBucketIndex(target)
    var closest []*PeerNode

    for offset := 0; offset < NodeIDBits && len(closest) < count; offset++ {
        idx := bucketIdx + offset
        if idx < NodeIDBits {
            for _, node := range d.RoutingTable[idx].GetClosest(count - len(closest)) {
                closest = append(closest, node)
            }
        }

        idx = bucketIdx - offset
        if idx >= 0 && idx != bucketIdx+offset {
            for _, node := range d.RoutingTable[idx].GetClosest(count - len(closest)) {
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
        d.StoreMu.RLock()
        data, ok := d.Store[msg.Key]
        d.StoreMu.RUnlock()

        if ok {
            response := struct {
                Type  string `json:"type"`
                Value []byte `json:"value"`
            }{
                Type:  "FIND_VALUE_RESPONSE",
                Value: data.Value,
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
        d.StoreMu.Lock()
        d.Store[msg.Key] = StoredData{
            Value:     msg.Value,
            Timestamp: time.Now(),
            TTL:       24 * time.Hour,
        }
        d.StoreMu.Unlock()
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
            if d.RoutingTable[bucketIdx].Len() > 0 {
                nodes := d.RoutingTable[bucketIdx].GetClosest(1)
                if len(nodes) > 0 {
                    d.IterativeFindNode(nodes[0].ID)
                }
            }
        }
    }
}

func (d *KademliaDHT) republishLoop() {
    ticker := time.NewTicker(12 * time.Hour)
    defer ticker.Stop()

    for {
        select {
        case <-d.ctx.Done():
            return
        case <-ticker.C:
            d.StoreMu.RLock()
            for key, data := range d.Store {
                if time.Since(data.Timestamp) > data.TTL/2 {
                    go d.StoreValue(key, data.Value)
                }
            }
            d.StoreMu.RUnlock()
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
                removed += d.RoutingTable[i].RemoveStalePeers()
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
        count += d.RoutingTable[i].Len()
    }
    return count
}

func (d *KademliaDHT) GetPeers() []*PeerNode {
    var peers []*PeerNode
    for i := 0; i < NodeIDBits; i++ {
        peers = append(peers, d.RoutingTable[i].GetClosest(KademliaBucketSize)...)
    }
    return peers
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

// ========== ENCRYPTED DATABASE ==========

type EncryptedDatabase struct {
    path        string
    crypto      *CryptoHelper
    mu          sync.RWMutex
    markets     map[string]*Market
    betOffers   map[string]*BetOffer
    acceptances map[string]*Acceptance
    resolutions map[string]*Resolution
    disputes    map[string]*Dispute
    complaints  map[string]*Complaint
    oracles     map[string]*OracleAnnouncement
}

func NewEncryptedDatabase(path string, password string) (*EncryptedDatabase, error) {
    if err := os.MkdirAll(path, 0700); err != nil {
        return nil, fmt.Errorf("failed to create db dir: %w", err)
    }

    crypto, err := NewCryptoHelper(password)
    if err != nil {
        return nil, err
    }

    db := &EncryptedDatabase{
        path:        path,
        crypto:      crypto,
        markets:     make(map[string]*Market),
        betOffers:   make(map[string]*BetOffer),
        acceptances: make(map[string]*Acceptance),
        resolutions: make(map[string]*Resolution),
        disputes:    make(map[string]*Dispute),
        complaints:  make(map[string]*Complaint),
        oracles:     make(map[string]*OracleAnnouncement),
    }

    if err := db.load(); err != nil {
        return nil, err
    }
    return db, nil
}

func (db *EncryptedDatabase) encryptAndSave(data interface{}, filename string) error {
    jsonData, err := json.MarshalIndent(data, "", "  ")
    if err != nil {
        return err
    }
    
    encrypted, err := db.crypto.Encrypt(jsonData)
    if err != nil {
        return err
    }
    
    saltFile := filename + ".salt"
    if err := os.WriteFile(filepath.Join(db.path, saltFile), db.crypto.salt, 0600); err != nil {
        return err
    }
    
    return os.WriteFile(filepath.Join(db.path, filename), encrypted, 0600)
}

func (db *EncryptedDatabase) loadAndDecrypt(data interface{}, filename string) error {
    encryptedPath := filepath.Join(db.path, filename)
    if _, err := os.Stat(encryptedPath); os.IsNotExist(err) {
        return nil
    }
    
    encrypted, err := os.ReadFile(encryptedPath)
    if err != nil {
        return err
    }
    
    saltPath := filepath.Join(db.path, filename+".salt")
    salt, err := os.ReadFile(saltPath)
    if err != nil {
        salt = db.crypto.salt
    }
    
    crypto := NewCryptoHelperWithSalt(string(db.crypto.password), salt)
    decrypted, err := crypto.Decrypt(encrypted)
    if err != nil {
        return err
    }
    
    return json.Unmarshal(decrypted, data)
}

func (db *EncryptedDatabase) load() error {
    if err := db.loadAndDecrypt(&db.markets, "markets.enc"); err != nil {
        return err
    }
    if err := db.loadAndDecrypt(&db.betOffers, "bets.enc"); err != nil {
        return err
    }
    if err := db.loadAndDecrypt(&db.acceptances, "acceptances.enc"); err != nil {
        return err
    }
    if err := db.loadAndDecrypt(&db.resolutions, "resolutions.enc"); err != nil {
        return err
    }
    if err := db.loadAndDecrypt(&db.disputes, "disputes.enc"); err != nil {
        return err
    }
    if err := db.loadAndDecrypt(&db.complaints, "complaints.enc"); err != nil {
        return err
    }
    if err := db.loadAndDecrypt(&db.oracles, "oracles.enc"); err != nil {
        return err
    }
    return nil
}

func (db *EncryptedDatabase) save() error {
    db.mu.RLock()
    defer db.mu.RUnlock()
    
    if err := db.encryptAndSave(db.markets, "markets.enc"); err != nil {
        return err
    }
    if err := db.encryptAndSave(db.betOffers, "bets.enc"); err != nil {
        return err
    }
    if err := db.encryptAndSave(db.acceptances, "acceptances.enc"); err != nil {
        return err
    }
    if err := db.encryptAndSave(db.resolutions, "resolutions.enc"); err != nil {
        return err
    }
    if err := db.encryptAndSave(db.disputes, "disputes.enc"); err != nil {
        return err
    }
    if err := db.encryptAndSave(db.complaints, "complaints.enc"); err != nil {
        return err
    }
    if err := db.encryptAndSave(db.oracles, "oracles.enc"); err != nil {
        return err
    }
    return nil
}

func (db *EncryptedDatabase) AddMarket(m *Market) error {
    db.mu.Lock()
    defer db.mu.Unlock()
    db.markets[m.ID] = m
    return db.save()
}

func (db *EncryptedDatabase) GetMarket(id string) (*Market, bool) {
    db.mu.RLock()
    defer db.mu.RUnlock()
    m, ok := db.markets[id]
    return m, ok
}

func (db *EncryptedDatabase) ListMarkets(includeExpired bool) []*Market {
    db.mu.RLock()
    defer db.mu.RUnlock()
    var list []*Market
    currentHeight, _ := currentMoneroBlockHeight()
    for _, m := range db.markets {
        if !includeExpired && m.ResolutionBlock+7200 < currentHeight {
            continue
        }
        list = append(list, m)
    }
    return list
}

func (db *EncryptedDatabase) UpdateMarketLiability(marketID string, additional uint64) error {
    db.mu.Lock()
    defer db.mu.Unlock()
    if m, ok := db.markets[marketID]; ok {
        m.UsedLiability += additional
        return db.save()
    }
    return fmt.Errorf("market not found")
}

func (db *EncryptedDatabase) AddBetOffer(b *BetOffer) error {
    db.mu.Lock()
    defer db.mu.Unlock()
    
    for _, existing := range db.betOffers {
        if existing.DepositTxID == b.DepositTxID {
            return fmt.Errorf("deposit transaction %s already used", b.DepositTxID[:16])
        }
        if existing.MarketID == b.MarketID && 
           existing.Nonce == b.Nonce && 
           string(existing.BettorSigningKey) == string(b.BettorSigningKey) {
            return fmt.Errorf("duplicate bet offer detected")
        }
    }
    db.betOffers[b.ID] = b
    return db.save()
}

func (db *EncryptedDatabase) GetBetOffersForMarket(marketID string, status string) []*BetOffer {
    db.mu.RLock()
    defer db.mu.RUnlock()
    var list []*BetOffer
    for _, b := range db.betOffers {
        if b.MarketID == marketID && (status == "" || b.Status == status) {
            list = append(list, b)
        }
    }
    return list
}

func (db *EncryptedDatabase) GetMyBets(bettorKey []byte) []*BetOffer {
    db.mu.RLock()
    defer db.mu.RUnlock()
    var list []*BetOffer
    for _, b := range db.betOffers {
        if bytes.Equal(b.BettorSigningKey, bettorKey) {
            list = append(list, b)
        }
    }
    return list
}

func (db *EncryptedDatabase) UpdateBetOfferStatus(id string, status string) error {
    db.mu.Lock()
    defer db.mu.Unlock()
    if b, ok := db.betOffers[id]; ok {
        b.Status = status
        return db.save()
    }
    return fmt.Errorf("bet offer not found")
}

func (db *EncryptedDatabase) AddAcceptance(a *Acceptance) error {
    db.mu.Lock()
    defer db.mu.Unlock()
    db.acceptances[a.BetOfferID] = a
    return db.save()
}

func (db *EncryptedDatabase) GetAcceptance(betOfferID string) (*Acceptance, bool) {
    db.mu.RLock()
    defer db.mu.RUnlock()
    a, ok := db.acceptances[betOfferID]
    return a, ok
}

func (db *EncryptedDatabase) AddResolution(r *Resolution) error {
    db.mu.Lock()
    defer db.mu.Unlock()
    db.resolutions[r.MarketID] = r
    return db.save()
}

func (db *EncryptedDatabase) GetResolution(marketID string) (*Resolution, bool) {
    db.mu.RLock()
    defer db.mu.RUnlock()
    r, ok := db.resolutions[marketID]
    return r, ok
}

func (db *EncryptedDatabase) AddDispute(d *Dispute) error {
    db.mu.Lock()
    defer db.mu.Unlock()
    db.disputes[d.ID] = d
    return db.save()
}

func (db *EncryptedDatabase) AddComplaint(c *Complaint) error {
    db.mu.Lock()
    defer db.mu.Unlock()
    db.complaints[c.ID] = c
    return db.save()
}

func (db *EncryptedDatabase) AddOracle(oa *OracleAnnouncement) error {
    db.mu.Lock()
    defer db.mu.Unlock()
    db.oracles[oa.ID] = oa
    return db.save()
}

func (db *EncryptedDatabase) GetOracles() []*OracleAnnouncement {
    db.mu.RLock()
    defer db.mu.RUnlock()
    var list []*OracleAnnouncement
    for _, o := range db.oracles {
        list = append(list, o)
    }
    return list
}

func (db *EncryptedDatabase) GetBetOfferForID(id string) (*BetOffer, bool) {
    db.mu.RLock()
    defer db.mu.RUnlock()
    b, ok := db.betOffers[id]
    return b, ok
}

func (db *EncryptedDatabase) ExportBackup() error {
    db.mu.RLock()
    defer db.mu.RUnlock()

    backup := struct {
        Timestamp   uint64                       `json:"timestamp"`
        Markets     map[string]*Market           `json:"markets"`
        BetOffers   map[string]*BetOffer         `json:"bet_offers"`
        Acceptances map[string]*Acceptance       `json:"acceptances"`
    }{
        Timestamp:   uint64(time.Now().Unix()),
        Markets:     db.markets,
        BetOffers:   db.betOffers,
        Acceptances: db.acceptances,
    }

    jsonData, err := json.MarshalIndent(backup, "", "  ")
    if err != nil {
        return err
    }
    
    encrypted, err := db.crypto.Encrypt(jsonData)
    if err != nil {
        return err
    }

    filename := fmt.Sprintf("prediction_backup_%d.enc", backup.Timestamp)
    return os.WriteFile(filename, encrypted, 0600)
}

// ========== MONERO CLIENT ==========

type MoneroClient struct {
    client   *walletrpc.Client
    ctx      context.Context
    username string
    password string
}

func NewMoneroClient(username, password string) (*MoneroClient, error) {
    ctx := context.Background()

    httpClient := &http.Client{
        Transport: httpdigest.New(username, password),
    }

    client := walletrpc.New(walletrpc.Config{
        Address: "http://127.0.0.1:18082/json_rpc",
        Client:  httpClient,
    })

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
    }, nil
}

func (m *MoneroClient) GetCurrentBlockHeight() (uint64, error) {
    return currentMoneroBlockHeight()
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
    resp, err :=
