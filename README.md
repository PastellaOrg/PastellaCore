![image](https://raw.githubusercontent.com/PastellaProject/Pastella/main/src/config/logo-small.png)


![Repo Size](https://img.shields.io/github/repo-size/PastellaOrg/PastellaCore?label=Project+Size)
![License](https://img.shields.io/github/license/PastellaOrg/PastellaCore?label=License)
![Download Count](https://img.shields.io/github/downloads/PastellaOrg/PastellaCore/total.svg?label=Downloads)
![Open Issue Count](https://img.shields.io/github/issues/PastellaOrg/PastellaCore?label=Issues)
![Version](https://img.shields.io/github/v/release/PastellaOrg/PastellaCore?label=Version)

****

## Table of Contents

- [Resources](#resources)
- [Key Features](#key-features)
  - [Consensus & Security](#consensus--security)
  - [Governance & Staking](#governance--staking)
  - [Economic Model](#economic-model)
  - [Transaction Features](#transaction-features)
- [Coin Specifications](#coin-specifications)
  - [Basic Info](#basic-info)
  - [Supply & Emission](#supply--emission)
  - [Block Parameters](#block-parameters)
  - [Network Ports](#network-ports)
  - [Genesis Details](#genesis-details)
  - [Transaction Parameters](#transaction-parameters)
- [Installing](#installing)
- [Credits](#credits)


# Pastella Protocol

**Pastella Protocol** is a next-generation blockchain platform featuring hybrid consensus, on-chain governance, and advanced economic mechanisms.



## Resources

| Resource | Link |
|----------|-----|
| **Official Website** | [pastella.org](https://pastella.org) |
| **Official Pool** | [pool.pastella.org](https://pool.pastella.org/) |
| **Block Explorer** | [explorer.pastella.org](https://explorer.pastella.org/) |
| **Source Code** | [github.com/PastellaOrg/PastellaCore](https://github.com/PastellaOrg/PastellaCore) |
| **Documentation** | [docs.pastella.org](https://docs.pastella.org) |
| **Whitepaper** | [whitepaper.pastella.org](https://whitepaper.pastella.org) |
| **Community Discord** | [discord.gg/9jqwc4UWrK](https://discord.gg/9jqwc4UWrK) |
| **Subreddit** | [reddit.com/r/PastellaOrg](https://reddit.com/r/PastellaOrg) |
| **X** | [x.com/PastellaOrg](https://x.com/PastellaOrg) |



## Key Features

### Consensus & Security

| Feature | Description |
|---------|-------------|
| **Hybrid Consensus** | Combines RandomX Proof-of-Work with Simple Reward Staking for robust network security |
| **RandomX Algorithm** | ASIC-resistant CPU-friendly hashing for fair mining distribution |
| **30-Second Blocks** | Fast confirmation times with efficient block propagation |

### Governance & Staking

| Feature | Description |
|---------|-------------|
| **On-Chain Governance** | Decentralized proposal and voting system for protocol upgrades and parameter changes |
| **Multi-Tier Staking** | Lock PAS for 1-5 years and earn variable rewards (5%-50% APY) |
| **Voting Power Integration** | Longer staking periods provide voting multipliers for greater governance influence |
| **Transparent Blockchain** | Direct address tracking for enhanced compliance and auditability |

### Economic Model

| Feature | Description |
|---------|-------------|
| **Controlled Emission** | 16 billion PAS total supply with yearly halving over 10 years |
| **Fair Distribution** | 5% premine for development, 95% mined by community over time |
| **Minimum Fee** | Fixed 1000 tints (0.00001 PAS) minimum fee for reliable transactions |
| **Dynamic Block Size** | Adaptive block sizing based on network demand |

### Transaction Features

| Feature | Description |
|---------|-------------|
| **Fast Transactions** | Near-instant confirmations with 30-second block times |
| **Multiple Outputs** | Send to multiple recipients in a single transaction |
| **Locked Transfers** | Time-locked transfers for vesting or payment schedules |
| **Transparent Addresses** | No complex stealth addressing - simple, auditable transactions |

---

## Coin Specifications

| Parameter | Value |
|-----------|-------|
| **Coin Name** | Pastella |
| **Ticker Symbol** | PAS |
| **Decimal Places** | 8 |
| **Network Type** | Transparent |

### Supply & Emission

| Parameter | Value |
|-----------|-------|
| **Total Supply** | 16,000,000 PAS (16 million) |
| **Genesis Reward** | 800,000 PAS (800 thousand - 5% premine) |
| **Block Reward** | 4 PAS |
| **Emission Model** | Yearly halving over 10 years |
| **Halving Interval** | 1,051,200 blocks (~1 year) |

### Block Parameters

| Parameter | Value |
|-----------|-------|
| **Block Time** | 30 seconds |
| **Blocks Per Day** | 2,880 |
| **Blocks Per Year** | 1,051,200 |
| **Difficulty Target** | 30 seconds |
| **Algorithm** | RandomX |

### Network Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 21000 | P2P | Peer-to-peer network |
| 21001 | RPC | JSON-RPC API |
| 21002 | Service | Additional services |

### Genesis Details

| Parameter | Value |
|-----------|-------|
| **Genesis Timestamp** | 1772132400 (Feb 26, 2026, 20:00:00 GMT+1) |
| **Start Difficulty** | 1000 |

### Transaction Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| **Minimum Fee** | 1000 tints (0.00001000 PAS) | Fixed minimum fee |
| **Maximum TX Size** | 1,000,000 bytes | ~1 MB |
| **Maximum Block Size** | 500,000,000 bytes | ~500 MB (dynamic) |
| **Unlock Time** | 10 blocks minimum | ~5 minutes |

---

### Installing

You can download the latest binary images from here: https://github.com/PastellaOrg/PastellaCore/releases

For compilation instructions, see [COMPILE_FROM_SOURCE.md](docs/COMPILE_FROM_SOURCE.md).

---

### Credits

**Pastella Team**

**Inherited from:**
- CryptoNote Developers
- Bytecoin Developers
- Monero Developers
- TurtleCoin Community

****
