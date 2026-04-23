```markdown
# Prediction Market Client

A fully decentralized, peer-to-peer prediction market over I2P with Monero settlement. No central servers, no smart contracts, no oracles you don't choose.

## What This Is

This software lets you create prediction markets or bet on existing ones. Every bet is a bilateral fixed-odds contract between exactly two people: a market maker and a bettor. The market maker posts odds, locks a bond, and acts as the oracle. The bettor wagers Monero. When the event resolves, the market maker pays winners. A 2% developer fee is deducted from each payout.

The network uses a Kademlia DHT over I2P for peer discovery and message propagation. No blockchain is used for consensus. No global state exists. Each client only needs to find counterparties and verify contracts locally.

## Requirements

- Go 1.21 or higher
- Monero node (monerod) running locally with RPC enabled
- monero-wallet-rpc running locally with authentication
- I2P router running with SAM enabled (i2prouter or i2pd)

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/prediction-market.git
cd prediction-market
go mod init prediction-market
go get github.com/majestrate/i2p-tools/sam3
go get gitlab.com/moneropay/go-monero/walletrpc
go get github.com/gabstv/httpdigest
go get golang.org/x/crypto/nacl/box
go get golang.org/x/crypto/scrypt
go build -o prediction-client main.go
```

Setup

1. Start Monero Daemon

```bash
monerod --rpc-bind-port=18081
```

2. Create and Run Monero Wallet RPC

First create a wallet file if you don't have one:

```bash
monero-wallet-cli --generate-new-wallet mywallet.bin
```

Then run the wallet RPC with authentication:

```bash
monero-wallet-rpc --wallet-file mywallet.bin --password yourwalletpass --rpc-bind-port 18082 --rpc-login myuser:mypass --daemon-address 127.0.0.1:18081
```

3. Start I2P Router

Using i2prouter:

```bash
i2prouter start
```

Or using i2pd:

```bash
i2pd --sam.enabled=true --sam.port=7656
```

4. Set Environment Variables

```bash
export XMR_RPC_USER=myuser
export XMR_RPC_PASS=mypass
```

5. Run the Client

```bash
./prediction-client
```

You will be prompted for a database password. This encrypts your keys and bet history locally. Choose something secure and remember it.

First Time Usage

When you first run the client, you have no peers. The network cannot find you yet. You need to add at least one existing peer.

Select option 11 from the main menu and paste an I2P address of an existing peer. You can find peer addresses on the project website or from other users.

After adding one peer, the DHT will automatically discover all other peers on the network within 1-2 minutes.

How to Use

Post a Market

Select option 1. You will need:

· Event name and description
· Resolution block height (Monero block number when the event is decided)
· Odds as a ratio (example: 2 1 means the market maker pays 2 units for every 1 unit wagered)
· Maximum liability in XMR (how much the market maker is willing to lose)
· A bond of 0.5 XMR (locked and returned after honest resolution)

The market maker must send the bond to a generated address. Once confirmed, the market is published to the DHT.

Browse and Bet

Select option 2 to see all active markets. Each entry shows the event name, odds, remaining liability, and resolution block.

To place a bet:

1. Enter your payout subaddress (from your Monero wallet)
2. Choose Yes or No
3. Enter your wager amount
4. Confirm the bet summary showing your potential payout after fees

The client generates a deposit address. Send exactly the wager amount to that address. Once confirmed, your bet offer is published to the DHT.

The market maker's client automatically accepts valid bets. You will see a confirmation when your bet is accepted.

Resolve a Market

If you are a market maker, select option 4 to resolve your market. You can only resolve after the resolution block height has passed. Choose the actual outcome (Yes or No). The client automatically pays all winning bettors and deducts the 2% developer fee. Winning bettors receive their payout directly to the subaddress they provided.

File a Dispute

If a market maker resolves dishonestly, select option 5 to file a dispute. This creates a permanent public record attached to the market maker's signing key. Selected oracles review the dispute and publish verdicts. Dishonest resolutions affect the maker's reputation.

File a Non-Resolution Complaint

If a market maker disappears without resolving by the deadline, select option 6 to file a complaint. The first bettor to file a valid complaint can claim the market maker's bond.

Become an Oracle

Select option 7 to announce yourself as an oracle. You must stake at least 10 XMR. The stake is for reputation only and cannot be slashed on-chain. Oracles are selected deterministically for disputes based on the market ID and resolution block height.

Peer Discovery

The client uses a Kademlia DHT running over I2P. When you add your first peer, the DHT recursively discovers all other peers in the network. No central bootstrap servers are required after that.

Peers expire after 1 hour of no contact and are automatically cleaned up. Peer scores persist across restarts to prevent Sybil attacks.

Security

· All local data is encrypted with AES-256-GCM using your database password
· Identity keys are encrypted with the same password
· Monero wallet RPC requires HTTP Digest authentication
· I2P addresses are validated before connection attempts
· Rate limiting prevents DDoS attacks
· Bet offers are deduplicated by deposit transaction ID plus market ID plus nonce plus bettor key
· Resolution deadlines are enforced by checking the actual Monero block height

Network Identifiers

The network is identified by a genesis hash hardcoded into the client:

740cb5dbb3b0fabecc7d7ddb58855838460482bc9b8faec461f4f02a53d12013

Only clients using this exact genesis hash can interoperate. If you change it, you create a separate network.

Developer Fee

A 2% developer fee is deducted from every payout and sent to the hardcoded developer Monero address:

855cmMVm1rXCAaDoqWjdFwgPwFZGeXr8bMBGX4cBiEEUWSt4Y3uX531GTM9QYm9BvRR3rNz22G4zN7djRxcwWgao25fW69C

The fee is automatically collected when a market is resolved. No action is required from users.

Recovery

If you lose your local database, you can recover your identity using the mnemonic phrase shown when you first ran the client.

Run with the recovery flag:

```bash
./prediction-client --recover
```

Enter your mnemonic when prompted. The client will regenerate your keys and scan the DHT for your historical bets.

Backup

The client automatically exports encrypted backups every hour. You can also manually export a backup using option 9. Store backups on external media.

Troubleshooting

Cannot connect to monero-wallet-rpc

Make sure the wallet RPC is running with the correct port and login. Check that XMR_RPC_USER and XMR_RPC_PASS environment variables match the login you used.

Cannot connect to I2P SAM bridge

Make sure your I2P router is running. For i2pd, you need --sam.enabled=true. The default SAM port is 7656.

No peers found

You need to add at least one peer manually using option 11. Get a peer address from the project website or from another user.

Bond or deposit not confirmed

Monero transactions take time. The client waits up to 120 seconds for bonds and 240 seconds for bets. Make sure your monerod is fully synced.

License

MIT

```

This README gives users everything they need to install, run, and use the prediction market client. No diagrams, no tables, just plain text instructions.
