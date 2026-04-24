```markdown
# Prediction Market Client

A fully decentralized, peer-to-peer prediction market over I2P with Monero settlement. No central servers, no smart contracts, no oracles you don't choose.

## What This Is

This software lets you create prediction markets or bet on existing ones. Every bet is a bilateral fixed-odds contract between exactly two people: a market maker and a bettor. The market maker posts odds, locks a bond, and proposes resolution outcomes. The bettor wagers Monero.

When the event's resolution block arrives, the market maker submits a resolution proposal with justification (citing sources). Active oracles on the network review the proposal and vote. If 3-5 oracles approve, the market resolves and winners are paid automatically. A 2% developer fee is deducted from each payout.

The network uses a Kademlia DHT over I2P for peer discovery and message propagation. No blockchain is used for consensus. No global state exists. Each client only needs to find counterparties and verify contracts locally.

## Requirements

- Go 1.21 or higher
- Monero node (monerod) running locally with RPC enabled
- monero-wallet-rpc running locally with authentication
- I2P router running with SAM enabled (i2prouter or i2pd)

## Installation

```bash
git clone https://github.com/unfortunateriver/InternetZero
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

Start Monero Daemon

```bash
monerod --rpc-bind-port=18081
```

Create and Run Monero Wallet RPC

First create a wallet file if you don't have one:

```bash
monero-wallet-cli --generate-new-wallet mywallet.bin
```

Then run the wallet RPC with authentication:

```bash
monero-wallet-rpc --wallet-file mywallet.bin --password yourwalletpass --rpc-bind-port 18082 --rpc-login myuser:mypass --daemon-address 127.0.0.1:18081
```

Start I2P Router

Using i2prouter:

```bash
i2prouter start
```

Or using i2pd:

```bash
i2pd --sam.enabled=true --sam.port=7656
```

Set Environment Variables

```bash
export XMR_RPC_USER=myuser
export XMR_RPC_PASS=mypass
```

Run the Client

```bash
./prediction-client
```

You will be prompted for a database password. This encrypts your identity and keys locally. Choose something secure and remember it.

First Time Usage

When you first run the client, you have the option to:

· Load an existing identity (if you have an identity.enc file)
· Create a new identity

If creating a new identity, you will be asked if you want to register as an oracle. Oracles stake XMR and vote on resolution proposals. See the "Become an Oracle" section below.

After identity setup, you have no peers. The network cannot find you yet. You need to add at least one existing peer.

Select option 10 from the main menu and paste an I2P address of an existing peer. You can find peer addresses on the project website or from other users.

After adding one peer, the DHT will automatically discover all other peers on the network within 1-2 minutes.

How to Use

Post a Market

Select option 1. You will need:

· Event name and description
· Resolution block height (Monero block number when the event is decided. Must be greater than current block height to prevent scams)
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
5. The client generates a deposit address. Send exactly the wager amount to that address
6. Once confirmed, your bet offer is published to the DHT

The market maker's client automatically accepts valid bets. You will see a confirmation when your bet is accepted.

Propose a Market Resolution (Market Makers)

Select option 4 to propose a resolution for your market. You can only propose after the resolution block height has passed.

When proposing:

1. Enter your justification (cite sources, explain your reasoning)
2. Type "+++" on a new line when done
3. Choose the outcome (Yes or No)

The proposal is sent to active oracles on the network. Oracles will review your justification and vote. Once 3-5 oracles approve, the market automatically resolves and winners are paid.

If not enough oracles are found within 10 hours, the market resolves according to the maker's decision.

File a Dispute

If a market maker resolves dishonestly, select option 5 to file a dispute. This creates a permanent public record attached to the market maker's signing key. The dispute can be reviewed but enforcement requires the oracle system.

File a Non-Resolution Complaint

If a market maker disappears without proposing a resolution by the deadline, select option 6 to file a complaint. The first bettor to file a valid complaint can claim the market maker's bond.

Become an Oracle

Select option 7 to announce yourself as an oracle. You must:

1. Stake at least 10 XMR (sent to a generated address)
2. Wait for confirmation

Oracles are selected deterministically for resolution proposals based on the market ID and resolution block height. When selected, you will see a notification:

```
🔔 NEW RESOLUTION PROPOSAL RECEIVED
   Market ID: [id]
   Proposed outcome: Yes/No
   Justification: [maker's reasoning]

   Type 'open' to review and vote, or 'FN' to reject this session.
```

Type "open" to review the justification, then "yes" to approve or "no" to reject. Your vote is recorded on the DHT. Oracles send heartbeat signals every 10 minutes to remain active. If an oracle does not respond within 10 hours, they are excluded from future votes.

Show Network Status

Select option 11 to see:

· Your node ID and I2P address
· Number of known peers
· Number of markets and bet offers in the DHT
· Number of active oracles currently online

Peer Discovery

The client uses a Kademlia DHT running over I2P. When you add your first peer, the DHT recursively discovers all other peers in the network. No central bootstrap servers are required after that.

Peers expire after 1 hour of no contact and are automatically cleaned up. All session data (discovered markets, peer routing tables) is deleted when the client closes. Only your identity, active markets you created, and pending bets you placed are persisted.

Security

· Identity is encrypted with AES-256-GCM using your database password (only identity.enc is stored on disk)
· All session data is memory-only and deleted on exit
· Monero wallet RPC requires HTTP Digest authentication
· I2P addresses are validated before connection attempts
· Rate limiting prevents DDoS attacks
· Bet offers are deduplicated by deposit transaction ID, market ID, nonce, and bettor key
· Resolution deadlines are enforced by checking the actual Monero block height
· Past block heights are rejected when creating markets (prevents scams)

Network Identifiers

The network is identified by a genesis hash hardcoded into the client:

```
740cb5dbb3b0fabecc7d7ddb58855838460482bc9b8faec461f4f02a53d12013
```

Only clients using this exact genesis hash can interoperate. If you change it, you create a separate network.

Developer Fee

A 2% developer fee is deducted from every payout and sent to the hardcoded developer Monero address:

```
855cmMVm1rXCAaDoqWjdFwgPwFZGeXr8bMBGX4cBiEEUWSt4Y3uX531GTM9QYm9BvRR3rNz22G4zN7djRxcwWgao25fW69C
```

The fee is automatically collected when a market is resolved. No action is required from users.

Recovery

If you lose your identity.enc file, you cannot recover your identity. There are no seed phrases or backdoors. Keep your identity.enc file safe and backed up.

To restore an identity:

1. Copy your backed-up identity.enc and identity.salt files to ./prediction_data/
2. Run the client and enter the same password you used when creating the identity
3. Select "Load existing identity"

The client automatically saves your identity changes (new markets, pending bets) when you exit normally.

Backup

The client automatically saves your identity changes on exit. You can manually copy the identity.enc and identity.salt files to external storage for backup.

Troubleshooting

Cannot connect to monero-wallet-rpc

Make sure the wallet RPC is running with the correct port and login. Check that XMR_RPC_USER and XMR_RPC_PASS environment variables match the login you used.

Cannot connect to I2P SAM bridge

Make sure your I2P router is running. For i2pd, you need --sam.enabled=true. The default SAM port is 7656.

No peers found

You need to add at least one peer manually using option 10. Get a peer address from the project website or from another user.

Bond or deposit not confirmed

Monero transactions take time. The client waits up to 120 seconds for bonds and 240 seconds for bets. Make sure your monerod is fully synced.

Oracle not receiving proposals

Make sure your I2P router is running and you have active peers. Oracles need to be online and sending heartbeats to be selected. Check option 11 to verify your active oracle status.

Resolution proposal stuck

If your proposal is pending for more than 10 hours, the client will automatically fall back to maker's decision. Check option 2 to see if your market is still pending.

License

MIT

```

The README now reflects:
- The new resolution voting system (oracle approval)
- Heartbeat mechanism for oracle liveness
- Memory-only session data with only identity persistence
- Block height validation for new markets
- The updated option numbers (resolve moved to option 4, add peer at option 10, network status at option 11)
- Oracle voting commands ("open", "FN", "yes"/"no")
- Recovery via identity.enc file (no seed phrases)
- Proper troubleshooting for oracle-related issues
