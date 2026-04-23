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
    BettorKey
  ```go
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
    // Query monerod JSON-RPC using proper request
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

    // Test connection
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
    identity *UserIdentity
    ctx      context.Context
    cancel   context.CancelFunc
    mu       sync.RWMutex
}

func NewI2PNetwork(identity *UserIdentity) (*I2PNetwork, error) {
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

// ========== ENCRYPTED USER IDENTITY ==========

type UserIdentity struct {
    SigningPrivateKey ed25519.PrivateKey
    SigningPublicKey  ed25519.PublicKey
    I2PPrivateKey     ed25519.PrivateKey
    I2PPublicKey      ed25519.PublicKey
    MoneroSeed        string
}

func NewUserIdentity(dbPath, password, recoveryMnemonic string) (*UserIdentity, error) {
    identityPath := filepath.Join(dbPath, "identity.enc")
    saltPath := filepath.Join(dbPath, "identity.salt")
    
    if recoveryMnemonic != "" {
        fmt.Println("Recovery mode: Attempting to restore from mnemonic...")
    }

    if encData, err := os.ReadFile(identityPath); err == nil {
        salt, err := os.ReadFile(saltPath)
        if err != nil {
            return nil, fmt.Errorf("failed to read identity salt: %w", err)
        }
        
        crypto := NewCryptoHelperWithSalt(password, salt)
        jsonData, err := crypto.Decrypt(encData)
        if err != nil {
            return nil, fmt.Errorf("failed to decrypt identity (wrong password?): %w", err)
        }
        
        var identity UserIdentity
        if err := json.Unmarshal(jsonData, &identity); err != nil {
            return nil, err
        }
        return &identity, nil
    }

    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return nil, fmt.Errorf("failed to generate signing key: %w", err)
    }

    seedBytes := make([]byte, 32)
    if _, err := rand.Read(seedBytes); err != nil {
        return nil, fmt.Errorf("failed to generate seed: %w", err)
    }

    identity := &UserIdentity{
        SigningPrivateKey: priv,
        SigningPublicKey:  pub,
        MoneroSeed:        hex.EncodeToString(seedBytes),
    }

    jsonData, err := json.MarshalIndent(identity, "", "  ")
    if err != nil {
        return nil, err
    }
    
    crypto, err := NewCryptoHelper(password)
    if err != nil {
        return nil, err
    }
    
    encrypted, err := crypto.Encrypt(jsonData)
    if err != nil {
        return nil, err
    }
    
    if err := os.WriteFile(identityPath, encrypted, 0600); err != nil {
        return nil, err
    }
    if err := os.WriteFile(saltPath, crypto.salt, 0600); err != nil {
        return nil, err
    }

    return identity, nil
}

// ========== ORACLE SYSTEM ==========

type OracleSystem struct {
    db       *EncryptedDatabase
    monero   *MoneroClient
    identity *UserIdentity
    i2p      *I2PNetwork
}

func NewOracleSystem(db *EncryptedDatabase, monero *MoneroClient, identity *UserIdentity, i2p *I2PNetwork) *OracleSystem {
    return &OracleSystem{
        db:       db,
        monero:   monero,
        identity: identity,
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

    height, err := o.monero.GetCurrentBlockHeight()
    if err != nil {
        height = 0
    }
    announcement := &OracleAnnouncement{
        ID:            sha256Hash([]byte(stakeTxID)),
        StakingTxID:   stakeTxID,
        StakingAmount: stakeAmount,
        SigningKey:    o.identity.SigningPublicKey,
        I2PDest:       o.i2p.GetDestination(),
        BlockHeight:   height,
    }

    return o.db.AddOracle(announcement)
}

func (o *OracleSystem) SelectOracles(marketID string, resolutionBlock uint64) []*OracleAnnouncement {
    seed := sha256.Sum256([]byte(fmt.Sprintf("%s|%d", marketID, resolutionBlock)))
    rng := binary.BigEndian.Uint64(seed[:8])

    oracles := o.db.GetOracles()
    if len(oracles) == 0 {
        return nil
    }

    selected := make([]*OracleAnnouncement, 0, 3)
    for i := 0; i < 3 && i < len(oracles); i++ {
        idx := int((rng + uint64(i)) % uint64(len(oracles)))
        selected = append(selected, oracles[idx])
    }
    return selected
}

// ========== MAIN CLIENT ==========

type PredictionClient struct {
    db        *EncryptedDatabase
    identity  *UserIdentity
    monero    *MoneroClient
    i2p       *I2PNetwork
    dht       *KademliaDHT
    oracleSys *OracleSystem
    reader    *bufio.Reader
    ctx       context.Context
    cancel    context.CancelFunc
    password  string
}

func NewPredictionClient(dbPath, password, recoveryMnemonic string) (*PredictionClient, error) {
    db, err := NewEncryptedDatabase(dbPath, password)
    if err != nil {
        return nil, fmt.Errorf("failed to init database: %w", err)
    }

    identity, err := NewUserIdentity(dbPath, password, recoveryMnemonic)
    if err != nil {
        return nil, fmt.Errorf("failed to init identity: %w", err)
    }

    moneroUser := os.Getenv("XMR_RPC_USER")
    moneroPass := os.Getenv("XMR_RPC_PASS")
    if moneroUser == "" {
        moneroUser = "default"
        moneroPass = "changeme"
        fmt.Println("\n⚠️ WARNING: Monero RPC using default credentials!")
        fmt.Println("   Set XMR_RPC_USER and XMR_RPC_PASS environment variables")
        fmt.Println("   And run monero-wallet-rpc with: --rpc-login user:pass")
    }
    
    monero, err := NewMoneroClient(moneroUser, moneroPass)
    if err != nil {
        return nil, err
    }

    i2p, err := NewI2PNetwork(identity)
    if err != nil {
        return nil, err
    }

    dht := NewKademliaDHT(i2p)
    if err := dht.Start(); err != nil {
        return nil, fmt.Errorf("failed to start DHT: %w", err)
    }

    oracleSys := NewOracleSystem(db, monero, identity, i2p)

    ctx, cancel := context.WithCancel(context.Background())

    return &PredictionClient{
        db:        db,
        identity:  identity,
        monero:    monero,
        i2p:       i2p,
        dht:       dht,
        oracleSys: oracleSys,
        reader:    bufio.NewReader(os.Stdin),
        ctx:       ctx,
        cancel:    cancel,
        password:  password,
    }, nil
}

func (c *PredictionClient) Run() {
    c.printBanner()
    c.printStakeSlashingDisclaimer()

    for {
        fmt.Println("\n┌────────────────────────────────────────────────────────────┐")
        fmt.Println("│                       MAIN MENU                             │")
        fmt.Println("├────────────────────────────────────────────────────────────┤")
        fmt.Println("│  1. Post a Market                                           │")
        fmt.Println("│  2. Browse Markets                                          │")
        fmt.Println("│  3. Check My Bets                                           │")
        fmt.Println("│  4. Resolve My Market (if maker)                            │")
        fmt.Println("│  5. File Dispute (dishonest resolution)                     │")
        fmt.Println("│  6. File Non-Resolution Complaint                           │")
        fmt.Println("│  7. Announce as Oracle                                      │")
        fmt.Println("│  8. Show My Identity                                        │")
        fmt.Println("│  9. Export Backup                                           │")
        fmt.Println("│ 10. Check Wallet Balance                                    │")
        fmt.Println("│ 11. Add Peer (join the network)                             │")
        fmt.Println("│ 12. Show Network Status                                     │")
        fmt.Println("│ 13. Exit                                                    │")
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
            c.resolveMarket()
        case "5":
            c.fileDispute()
        case "6":
            c.fileComplaint()
        case "7":
            c.announceOracle()
        case "8":
            c.showIdentity()
        case "9":
            c.exportBackup()
        case "10":
            c.checkBalance()
        case "11":
            c.addPeer()
        case "12":
            c.showNetworkStatus()
        case "13":
            fmt.Println("\nGoodbye!")
            c.cancel()
            return
        }
    }
}

func (c *PredictionClient) printBanner() {
    fmt.Printf("\n╔════════════════════════════════════════════════════════════════╗\n")
    fmt.Printf("║                    PREDICTION MARKET CLIENT                     ║\n")
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
    fmt.Println("║  Oracle stakes are for reputation only. No mechanism exists   ║")
    fmt.Println("║  to slash funds on-chain. Verify oracle honesty through       ║")
    fmt.Println("║  reputation scores and cross-reference multiple oracles.      ║")
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
        fmt.Println("   Must be a valid .i2p address or base32 string.")
        return
    }

    fmt.Println("\nConnecting to peer...")

    if err := c.dht.AddManualPeer(peerAddr); err != nil {
        fmt.Printf("❌ Failed to connect: %v\n", err)
        fmt.Println("\nMake sure:")
        fmt.Println("  - The I2P address is correct")
        fmt.Println("  - The peer is online")
        fmt.Println("  - Your I2P router is running")
        return
    }

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
    
    fmt.Println("\n┌────────────────────────────────────────────────────────────┐")
    fmt.Println("│                    NETWORK STATUS                           │")
    fmt.Println("└────────────────────────────────────────────────────────────┘")
    fmt.Printf("\n  Node ID:     %x\n", c.dht.NodeID[:8])
    fmt.Printf("  I2P Address: %s\n", c.i2p.GetBase32Address()[:40])
    fmt.Printf("  Known Peers: %d\n", peerCount)
    
    if peerCount == 0 {
        fmt.Println("\n⚠️ You are not connected to any peers!")
        fmt.Println("   Use option 11 to add a peer and join the network.")
    } else {
        fmt.Println("\n  Peers expire after 1 hour of no contact.")
        fmt.Println("  The DHT automatically discovers new peers.")
        
        peers := c.dht.GetPeers()
        fmt.Println("\n  Sample peers:")
        for i, p := range peers {
            if i >= 5 {
                break
            }
            fmt.Printf("    - %s... (last seen: %v ago)\n", 
                p.I2PDest[:20], 
                time.Since(p.LastSeen).Round(time.Second))
        }
        if len(peers) > 5 {
            fmt.Printf("    ... and %d more\n", len(peers)-5)
        }
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

    fmt.Print("Resolution block height (Monero block #): ")
    blockStr, _ := c.reader.ReadString('\n')
    blockHeight, err := strconv.ParseUint(strings.TrimSpace(blockStr), 10, 64)
    if err != nil {
        fmt.Printf("Invalid block height: %v\n", err)
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

    currentHeight, err := c.monero.GetCurrentBlockHeight()
    if err != nil {
        currentHeight = 0
    }

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

    if err := c.db.AddMarket(market); err != nil {
        fmt.Printf("Failed to save market: %v\n", err)
        return
    }

    marketData, _ := json.Marshal(market)
    if err := c.dht.StoreValue("market:"+market.ID, marketData); err != nil {
        fmt.Printf("Warning: Failed to store market in DHT: %v\n", err)
    }

    fmt.Printf("\n✅ Market created successfully!\n")
    fmt.Printf("   Market ID: %s\n", market.ID)
}

func (c *PredictionClient) browseMarkets() {
    fmt.Println("\n┌────────────────────────────────────────────────────────────┐")
    fmt.Println("│                    ACTIVE MARKETS                            │")
    fmt.Println("└────────────────────────────────────────────────────────────┘")

    markets := c.db.ListMarkets(false)
    if len(markets) == 0 {
        fmt.Println("\nNo markets found. Create one or wait for DHT discovery.")
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

    currentHeight, err := c.monero.GetCurrentBlockHeight()
    if err != nil {
        currentHeight = 0
    }

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

    if err := c.db.AddBetOffer(bet); err != nil {
        fmt.Printf("Failed to save bet: %v\n", err)
        return
    }

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
        if acc, ok := c.db.GetAcceptance(betID); ok {
            fmt.Printf("\n🎉 Bet ACCEPTED by maker %x...\n", acc.MakerKey[:8])
            c.db.UpdateBetOfferStatus(betID, "accepted")
            if bet, ok := c.db.GetBetOfferForID(betID); ok {
                c.db.UpdateMarketLiability(bet.MarketID, bet.WagerAmount)
            }
            return
        }
    }
    fmt.Printf("\n⏰ Bet %s still pending. Maker may accept later.\n", betID[:16])
}

func (c *PredictionClient) checkMyBets() {
    bets := c.db.GetMyBets(c.identity.SigningPublicKey)
    if len(bets) == 0 {
        fmt.Println("\nNo bets found.")
        return
    }

    fmt.Println("\n--- YOUR BETS ---")
    for _, bet := range bets {
        market, _ := c.db.GetMarket(bet.MarketID)
        marketName := "Unknown"
        if market != nil {
            marketName = market.EventName
        }
        fmt.Printf("\nBet on: %s\n", marketName)
        fmt.Printf("  Outcome: %v | Wager: %.4f XMR\n", bet.ChosenOutcome, float64(bet.WagerAmount)/1e12)
        fmt.Printf("  Status: %s\n", bet.Status)
    }
}

func (c *PredictionClient) resolveMarket() {
    markets := c.db.ListMarkets(true)
    var unresolved []*Market
    for _, m := range markets {
        if !m.Resolved {
            unresolved = append(unresolved, m)
        }
    }

    if len(unresolved) == 0 {
        fmt.Println("\nNo unresolvedmarkets.")
        return
    }

    fmt.Println("\n--- YOUR UNRESOLVED MARKETS ---")
    for i, m := range unresolved {
        fmt.Printf("%d. %s (resolves at block %d)\n", i+1, m.EventName, m.ResolutionBlock)
    }

    fmt.Print("\nSelect market to resolve: ")
    choiceStr, _ := c.reader.ReadString('\n')
    idx, err := strconv.Atoi(strings.TrimSpace(choiceStr))
    if err != nil || idx < 1 || idx > len(unresolved) {
        fmt.Println("Invalid selection")
        return
    }

    market := unresolved[idx-1]

    currentHeight, err := c.monero.GetCurrentBlockHeight()
    if err != nil {
        fmt.Printf("Failed to get current block height: %v\n", err)
        return
    }
    
    if currentHeight < market.ResolutionBlock {
        fmt.Printf("Cannot resolve yet. Resolution block %d (current: %d)\n", market.ResolutionBlock, currentHeight)
        return
    }

    fmt.Printf("Resolve '%s' as (yes/no): ", market.EventName)
    outcomeStr, _ := c.reader.ReadString('\n')
    outcome := strings.TrimSpace(outcomeStr) == "yes"

    resolution := &Resolution{
        MarketID:    market.ID,
        Outcome:     outcome,
        BlockHeight: currentHeight,
        MakerKey:    c.identity.SigningPublicKey,
    }

    resData := []byte(fmt.Sprintf("%s|%t|%d", market.ID, outcome, currentHeight))
    resolution.Signature = ed25519.Sign(c.identity.SigningPrivateKey, resData)

    if err := c.db.AddResolution(resolution); err != nil {
        fmt.Printf("Failed to save resolution: %v\n", err)
        return
    }

    resDataFull, _ := json.Marshal(resolution)
    if err := c.dht.StoreValue("resolution:"+market.ID, resDataFull); err != nil {
        fmt.Printf("Warning: Failed to store resolution in DHT: %v\n", err)
    }

    bets := c.db.GetBetOffersForMarket(market.ID, "accepted")
    paidCount := 0
    for _, bet := range bets {
        if bet.ChosenOutcome == outcome {
            payout := bet.WagerAmount * market.OddsNumerator / market.OddsDenominator
            afterFees := payout * (100 - DeveloperFeePercent - OracleFeePercent) / 100
            devFee := payout * DeveloperFeePercent / 100

            txHash, err := c.monero.SendPayout(bet.PayoutSubaddress, afterFees)
            if err != nil {
                fmt.Printf("Failed to pay %s: %v\n", bet.PayoutSubaddress[:16], err)
                continue
            }

            if devFee > 0 {
                if _, err := c.monero.SendDeveloperFee(devFee); err != nil {
                    fmt.Printf("Failed to send developer fee: %v\n", err)
                } else {
                    fmt.Printf("💰 Developer fee: %.4f XMR collected\n", float64(devFee)/1e12)
                }
            }

            fmt.Printf("✅ Paid %.4f XMR to bettor (tx: %s)\n", float64(afterFees)/1e12, txHash[:16])
            c.db.UpdateBetOfferStatus(bet.ID, "paid")
            paidCount++
        }
    }

    market.Resolved = true
    market.ResolutionOutcome = &outcome
    market.ResolutionBlockActual = currentHeight
    c.db.AddMarket(market)

    fmt.Printf("\n✅ Market resolved as '%s'\n", map[bool]string{true: "YES", false: "NO"}[outcome])
    fmt.Printf("   Paid %d winning bets\n", paidCount)
}

func (c *PredictionClient) fileDispute() {
    fmt.Println("\n--- FILE DISPUTE ---")
    fmt.Print("Market ID: ")
    marketID, _ := c.reader.ReadString('\n')
    marketID = strings.TrimSpace(marketID)

    market, ok := c.db.GetMarket(marketID)
    if !ok {
        fmt.Println("Market not found")
        return
    }

    resolution, ok := c.db.GetResolution(marketID)
    if !ok {
        fmt.Println("No resolution found for this market")
        return
    }

    fmt.Printf("Market: %s\n", market.EventName)
    fmt.Printf("Resolution: %v at block %d\n", resolution.Outcome, resolution.BlockHeight)
    fmt.Print("Do you dispute this resolution? (yes/no): ")
    confirm, _ := c.reader.ReadString('\n')
    if strings.TrimSpace(confirm) != "yes" {
        return
    }

    dispute := &Dispute{
        ID:             sha256Hash([]byte(fmt.Sprintf("%s|%s|%d", marketID, c.identity.SigningPublicKey, time.Now().Unix()))),
        MarketID:       marketID,
        ResolutionHash: sha256Hash([]byte(fmt.Sprintf("%s|%t", marketID, resolution.Outcome))),
        BettorKey:      c.identity.SigningPublicKey,
        Timestamp:      uint64(time.Now().Unix()),
        Status:         "pending",
    }

    if err := c.db.AddDispute(dispute); err != nil {
        fmt.Printf("Failed to file dispute: %v\n", err)
        return
    }

    disputeData, _ := json.Marshal(dispute)
    if err := c.dht.StoreValue("dispute:"+dispute.ID, disputeData); err != nil {
        fmt.Printf("Warning: Failed to store dispute in DHT: %v\n", err)
    }

    oracles := c.oracleSys.SelectOracles(marketID, resolution.BlockHeight)
    if len(oracles) > 0 {
        fmt.Printf("Selected %d oracles for adjudication.\n", len(oracles))
    }

    fmt.Println("Dispute recorded.")
}

func (c *PredictionClient) fileComplaint() {
    fmt.Println("\n--- FILE NON-RESOLUTION COMPLAINT ---")
    fmt.Print("Market ID: ")
    marketID, _ := c.reader.ReadString('\n')
    marketID = strings.TrimSpace(marketID)

    market, ok := c.db.GetMarket(marketID)
    if !ok {
        fmt.Println("Market not found")
        return
    }

    if market.Resolved {
        fmt.Println("Market already resolved")
        return
    }

    fmt.Print("File complaint? (yes/no): ")
    confirm, _ := c.reader.ReadString('\n')
    if strings.TrimSpace(confirm) != "yes" {
        return
    }

    var userBet *BetOffer
    for _, bet := range c.db.GetMyBets(c.identity.SigningPublicKey) {
        if bet.MarketID == marketID {
            userBet = bet
            break
        }
    }

    if userBet == nil {
        fmt.Println("No bet found from you on this market")
        return
    }

    complaint := &Complaint{
        ID:         sha256Hash([]byte(fmt.Sprintf("%s|%s|%d", marketID, c.identity.SigningPublicKey, time.Now().Unix()))),
        MarketID:   marketID,
        BetOfferID: userBet.ID,
        BettorKey:  c.identity.SigningPublicKey,
        Timestamp:  uint64(time.Now().Unix()),
    }

    if err := c.db.AddComplaint(complaint); err != nil {
        fmt.Printf("Failed to file complaint: %v\n", err)
        return
    }

    fmt.Printf("\n💰 Bond of %.4f XMR is claimable\n", float64(BondAmountPiconero)/1e12)
    fmt.Println("Complaint filed.")
}

func (c *PredictionClient) announceOracle() {
    fmt.Println("\n--- ANNOUNCE AS ORACLE ---")
    fmt.Printf("Minimum stake: %.4f XMR\n", float64(MinOracleStakePiconero)/1e12)
    fmt.Print("Stake amount (XMR): ")
    stakeStr, _ := c.reader.ReadString('\n')
    stakeXMR, err := strconv.ParseFloat(strings.TrimSpace(stakeStr), 64)
    if err != nil {
        fmt.Printf("Invalid amount: %v\n", err)
        return
    }

    stakeAmount := uint64(stakeXMR * 1e12)
    if stakeAmount < MinOracleStakePiconero {
        fmt.Printf("Stake must be at least %.4f XMR\n", float64(MinOracleStakePiconero)/1e12)
        return
    }

    if err := c.oracleSys.AnnounceAsOracle(stakeAmount); err != nil {
        fmt.Printf("Failed to announce as oracle: %v\n", err)
        return
    }

    fmt.Println("\n✅ Announced as oracle! You may be selected for dispute adjudication.")
}

func (c *PredictionClient) showIdentity() {
    fmt.Println("\n┌────────────────── YOUR IDENTITY ──────────────────┐")
    fmt.Printf("│ Signing Key:   %x...\n", c.identity.SigningPublicKey[:8])
    fmt.Printf("│ I2P Address:   %s...\n", c.i2p.GetBase32Address()[:20])
    fmt.Printf("│ DHT Node ID:   %x...\n", c.dht.NodeID[:8])
    fmt.Printf("│ Monero Seed:   %s...\n", c.identity.MoneroSeed[:16])
    fmt.Println("├────────────────────────────────────────────────────┤")
    fmt.Println("│ SAVE THESE SECURELY!                                │")
    fmt.Println("│                                                    │")
    fmt.Println("│ To share your I2P address with others:             │")
    fmt.Printf("│   %s\n", c.i2p.GetBase32Address())
    fmt.Println("└────────────────────────────────────────────────────┘")
}

func (c *PredictionClient) exportBackup() {
    if err := c.db.ExportBackup(); err != nil {
        fmt.Printf("Failed to export backup: %v\n", err)
        return
    }
    fmt.Println("\n✅ Backup exported to prediction_backup_*.enc")
    fmt.Println("   Store this on external media (USB drive, offline storage)")
}

func (c *PredictionClient) checkBalance() {
    balance, unlocked, err := c.monero.GetBalance()
    if err != nil {
        fmt.Printf("Failed to get balance: %v\n", err)
        return
    }

    fmt.Printf("\n💰 Wallet Balance:\n")
    fmt.Printf("   Total balance:   %.4f XMR\n", float64(balance)/1e12)
    fmt.Printf("   Unlocked:        %.4f XMR\n", float64(unlocked)/1e12)
}

// ========== MAIN ==========

func main() {
    fmt.Println("╔════════════════════════════════════════════════════════════════╗")
    fmt.Println("║                    PREDICTION MARKET CLIENT                    ║")
    fmt.Println("╚════════════════════════════════════════════════════════════════╝")
    fmt.Println()
    fmt.Println("REQUIRED PREREQUISITES:")
    fmt.Println("  1. Set up Monero with RPC authentication:")
    fmt.Println("     export XMR_RPC_USER=youruser")
    fmt.Println("     export XMR_RPC_PASS=yourpass")
    fmt.Println("     monero-wallet-rpc --wallet-file wallet.bin --rpc-bind-port 18082 --rpc-login youruser:yourpass")
    fmt.Println()
    fmt.Println("  2. Run monerod: monerod --rpc-bind-port=18081")
    fmt.Println("  3. Run I2P router (i2prouter start or i2pd --sam.enabled=true)")
    fmt.Println()
    fmt.Print("Enter database password (this encrypts your keys and bets): ")
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    password := scanner.Text()
    
    if len(password) < 8 {
        fmt.Println("Password must be at least 8 characters")
        os.Exit(1)
    }

    var recoveryMnemonic string
    if len(os.Args) > 1 && os.Args[1] == "--recover" {
        fmt.Print("Enter recovery mnemonic: ")
        scanner.Scan()
        recoveryMnemonic = scanner.Text()
    }

    client, err := NewPredictionClient("./prediction_data", password, recoveryMnemonic)
    if err != nil {
        fmt.Printf("FATAL: %v\n", err)
        fmt.Println("\nTroubleshooting:")
        fmt.Println("  - Is XMR_RPC_USER and XMR_RPC_PASS set?")
        fmt.Println("  - Is monero-wallet-rpc running with --rpc-login?")
        fmt.Println("  - Is monerod running with RPC enabled?")
        fmt.Println("  - Is I2P router running with SAM enabled?")
        os.Exit(1)
    }

    client.Run()
}
