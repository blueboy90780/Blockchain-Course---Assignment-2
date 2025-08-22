# Proof-of-Stake Blockchain (Go)

A minimal educational blockchain implementing:

- Blocks with SHA-256 linking and Merkle root
- Transactions and mempool
- Proof-of-Stake validator selection (stake-weighted deterministic lottery)
- Double-spend prevention via UTXO model (no nonces)
- Chain verification and immutability demo
- JSON persistence
- Interactive CLI

## Build and run

Prerequisites:
- Go 1.20+ (tested with Go 1.22), for my own local computer, I used Go 1.24.2

Running and compilign the Go application:
- go run main.go
Make sure you are in the same directory as the one which the main.go file is located in

Optional flags:
- -datadir <path>  # where pos_chain.json and wallets.json are stored

Run tests:
- go test ./...

## Transactions model

We use a simplified UTXO model:
- Each transaction consumes specific unspent outputs (inputs) and creates new outputs.
- Ownership is enforced via optional ECDSA P-256 signatures. When PubKey/Sig are provided, the signature is verified against a canonical SignableHash. If `from` is a 40-hex address, it must match the signer address; if it's an alias (e.g., `alice`), the signature can still be verified without strict address equality.
- A transaction is valid when total outputs do not exceed total inputs; mempool prevents double-spends of the same inputs. Multiple transactions from the same sender can be included in one block as long as they spend different UTXOs.
Merkle root is built over tx hashes for integrity.

## Wallets, aliases, and auto-signing

- Aliases: The demo names `alice`, `bob`, and `carol` are aliases (labels), not raw addresses. They appear in initial balances and can be used wherever an address is accepted.
- Addresses: A raw address is a 40-hex string derived from a public key (first 20 bytes of SHA-256 of the uncompressed pubkey).
- Key generation: `keygen` creates ECDSA P-256 keypairs for all current alias entries (and any addresses without keys) and writes them to `wallets.json`.
- Auto-signing: When you submit `tx <from> <to> <amount>` without a `privHex`, the CLI looks up `<from>` in `wallets.json` and, if a matching entry exists, automatically signs the transaction with that private key.
	- If `<from>` is an alias (e.g., `alice`) and a key exists for `alice`, the tx will be auto-signed.
	- If `<from>` is a 40-hex address and a matching entry exists under that exact address label in `wallets.json`, it will be auto-signed.
	- If no key is found, the tx is submitted unsigned (still valid in this educational chain). To force signing, provide `privHex` explicitly.
- Signature checks: When a signature is present, it must verify. If `from` is a 40-hex address, it must match the signer’s derived address. If `from` is an alias, the signature is still verified but strict address equality isn’t enforced.

## CLI usage

Run the program then type commands:

- `balances` — show balances
- `serve <host:port>` — start HTTP node (e.g., `serve 127.0.0.1:8080`)
- `peer add <addr>` | `peer list` — manage peers
- `sync` — fetch and adopt the longest valid chain from peers
- `stake <addr> <amount>` — set validator stake
- `tx <from> <to> <amount>` — submit a transaction
- `tx <from> <to> <amount> [privHex]` — submit a signed transaction when private key is provided; if omitted, the CLI will auto-sign using `wallets.json` if a matching entry exists
- `propose` — run PoS selection and add a block from the mempool
- `chain` — list blocks
- `verify` — verify chain link and hashes
- `tamper <index>` — mutate a block to demonstrate immutability checks failing
- `save` / `load` — persist and restore state from `pos_chain.json`
- `export` — print snapshot JSON to stdout
- `keygen` — generate keypairs for all existing users in current balances and save to `wallets.json`; prints address, pubkey, privkey for each created entry
- `quit` — exit

Example flow:

1. `balances`
2. `keygen`  # creates/updates wallets.json with keys for aliases (alice, bob, carol)
3. `tx alice bob 5`  # this auto-signs using alice’s key from wallets.json (no privHex needed)
3. `propose`
4. `verify` -> should be valid
5. `tamper 1` then `verify` -> should report inconsistency

## Networking (simplified P2P)

A minimal HTTP peer is included in `internal/p2p` for broadcasting transactions/blocks and syncing chains.

Endpoints:
- `POST /tx`    body: Transaction JSON
- `POST /block` body: Block JSON
- `GET  /chain` returns a Snapshot (blocks, state, stake)
- `GET/POST /peers` to list/add peers

Quick demo (two terminals):
1) Terminal A: `serve 127.0.0.1:8080` then `balances`.
2) Terminal B: `peer add 127.0.0.1:8080` then `sync` (this aligns genesis and state; required for accepting broadcasts).
3) Create `tx` on one node and `propose`; the node will broadcast to peers. Ensure both nodes share the same genesis (this repo uses a fixed genesis timestamp) or run `sync` before accepting broadcasts.

## PoS details

- Each validator has a stake amount. Total stake defines the lottery weights.
- The RNG seed is derived from the previous block hash and the next height, producing deterministic selection with stake-weighted probability.
- The winning validator is recorded with a `stakeProof` (seed hash) in the block, which is validated by nodes.

## Persistence

State is serialized to a JSON snapshot containing blocks, UTXO/balances, and stakes. On startup, the program loads `pos_chain.json` from the provided `-datadir` if present.

## Testing notes

- Double-spend: attempt two tx that spend the same input UTXO; the second is rejected at mempool entry. Spending two different UTXOs from the same sender in the same block is allowed.
- Immutability: use `tamper` to mutate a historical block; `verify` will flag the mismatch.

