package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"Assignment_2_Repo/internal/types"
	"Assignment_2_Repo/internal/wallet"
)

// StakeState holds each validator's stake amount.
type StakeState struct {
	Stakes map[string]uint64 `json:"stakes"`
}

// State holds UTXO set and a derived balance index for convenience.
type State struct {
	UTXO     map[string]types.TxOutput `json:"utxo"`
	Balances map[string]int64          `json:"balances"`
}

// Blockchain is the main chain object with PoS validator selection and persistence hooks.
type Blockchain struct {
	mu      sync.RWMutex
	blocks  []*types.Block
	mempool []types.Transaction
	state   *State
	stake   *StakeState
}

// BlockReward is the fixed reward paid to the selected validator per block.
const BlockReward int64 = 10

// GenesisTimestamp is fixed to ensure all nodes produce the same genesis hash.
const GenesisTimestamp int64 = 1700000000

// NewBlockchain creates a chain with a genesis block and initial balances/stakes.
func NewBlockchain(genesisBalances map[string]int64, genesisStakes map[string]uint64) *Blockchain {
	st := &State{Balances: map[string]int64{}, UTXO: map[string]types.TxOutput{}}
	for a, b := range genesisBalances {
		st.Balances[a] = b
		// Seed multiple UTXOs per account to enable multiple concurrent spends without conflicts.
		// We model a single "genesis transaction" per account with many outputs: indices 0..n-1.
		h := sha256.Sum256([]byte(fmt.Sprintf("genesis-%s-%d", a, b)))
		txid := hex.EncodeToString(h[:])
		const chunk int64 = 100
		if b <= chunk {
			st.UTXO[makeKey(txid, 0)] = types.TxOutput{To: a, Amount: b}
		} else {
			n := int(b / chunk)
			rem := b % chunk
			idx := 0
			for i := 0; i < n; i++ {
				st.UTXO[makeKey(txid, idx)] = types.TxOutput{To: a, Amount: chunk}
				idx++
			}
			if rem > 0 {
				st.UTXO[makeKey(txid, idx)] = types.TxOutput{To: a, Amount: rem}
			}
		}
	}
	ss := &StakeState{Stakes: map[string]uint64{}}
	for v, s := range genesisStakes {
		ss.Stakes[v] = s
	}

	// Create an empty genesis block with fixed values (deterministic across nodes)
	g := &types.Block{
		Index:      0,
		Timestamp:  GenesisTimestamp,
		PrevHash:   "",
		Txns:       []types.Transaction{},
		TxRoot:     types.ComputeMerkleRoot(nil),
		Validator:  "genesis",
		StakeProof: "",
	}
	g.Hash = g.ComputeHash()

	return &Blockchain{
		blocks:  []*types.Block{g},
		mempool: []types.Transaction{},
		state:   st,
		stake:   ss,
	}
}

// Head returns the last block.
func (bc *Blockchain) Head() *types.Block {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.blocks[len(bc.blocks)-1]
}

// Blocks returns a copy slice of blocks for read-only.
func (bc *Blockchain) Blocks() []*types.Block {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	out := make([]*types.Block, len(bc.blocks))
	copy(out, bc.blocks)
	return out
}

// Mempool returns a copy of the pending transactions in arrival order.
func (bc *Blockchain) Mempool() []types.Transaction {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	out := make([]types.Transaction, len(bc.mempool))
	copy(out, bc.mempool)
	return out
}

// SubmitTransaction adds a transaction to the mempool if valid against current state.
func (bc *Blockchain) SubmitTransaction(tx types.Transaction) error {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	// Basic validation: inputs must exist and belong to From, outputs sum must not exceed inputs sum
	if len(tx.Inputs) == 0 || len(tx.Outputs) == 0 {
		return errors.New("tx must have inputs and outputs")
	}
	// Verify signature when provided (optional for backward compatibility)
	if tx.From != "coinbase" && (tx.SigHex != "" || tx.PubKeyHex != "") {
		if tx.PubKeyHex == "" || tx.SigHex == "" {
			return errors.New("missing signature")
		}
		pubBytes, err := hex.DecodeString(tx.PubKeyHex)
		if err != nil {
			return fmt.Errorf("bad pubkey: %w", err)
		}
		pub, err := wallet.UnmarshalPubkey(pubBytes)
		if err != nil {
			return fmt.Errorf("bad pubkey: %w", err)
		}
		h := tx.SignableHash()
		ok, err := wallet.VerifyHash(pub, h[:], tx.SigHex)
		if err != nil || !ok {
			return errors.New("invalid signature")
		}
		// If From looks like a hex address (40 hex chars), require it to match signer address.
		// If From is an alias (e.g., "alice"), allow signature without strict address match.
		if isHexAddress(tx.From) {
			addr := wallet.AddressFromPublicKey(pub)
			if addr != tx.From {
				return errors.New("from does not match pubkey address")
			}
		}
	}
	inSum := int64(0)
	for _, in := range tx.Inputs {
		utxo, ok := bc.state.UTXO[makeKey(in.TxID, in.Index)]
		if !ok {
			return fmt.Errorf("input not found: %s:%d", in.TxID, in.Index)
		}
		if utxo.To != tx.From {
			return errors.New("input does not belong to sender")
		}
		inSum += utxo.Amount
	}
	outSum := int64(0)
	for _, out := range tx.Outputs {
		if out.Amount <= 0 {
			return errors.New("output amount must be positive")
		}
		outSum += out.Amount
	}
	if outSum > inSum {
		return errors.New("outputs exceed inputs")
	}
	// Check mempool duplicates by ID and prevent spending the same exact inputs twice
	reserved := map[string]struct{}{}
	for _, m := range bc.mempool {
		if m.ID == tx.ID {
			return errors.New("duplicate tx id in mempool")
		}
		for _, min := range m.Inputs {
			reserved[makeKey(min.TxID, min.Index)] = struct{}{}
		}
	}
	for _, in := range tx.Inputs {
		if _, exists := reserved[makeKey(in.TxID, in.Index)]; exists {
			return errors.New("conflicting pending spend of same input")
		}
	}
	bc.mempool = append(bc.mempool, tx)
	return nil
}

// ValidateAndApplyTx applies a transaction to state (used when sealing a block).
func (bc *Blockchain) validateAndApplyTx(st *State, tx types.Transaction) error {
	if len(tx.Inputs) == 0 || len(tx.Outputs) == 0 {
		return errors.New("tx must have inputs and outputs")
	}
	// Verify signature when provided (optional for backward compatibility)
	if tx.From != "coinbase" && (tx.SigHex != "" || tx.PubKeyHex != "") {
		if tx.PubKeyHex == "" || tx.SigHex == "" {
			return errors.New("missing signature")
		}
		pubBytes, err := hex.DecodeString(tx.PubKeyHex)
		if err != nil {
			return fmt.Errorf("bad pubkey: %w", err)
		}
		pub, err := wallet.UnmarshalPubkey(pubBytes)
		if err != nil {
			return fmt.Errorf("bad pubkey: %w", err)
		}
		h := tx.SignableHash()
		ok, err := wallet.VerifyHash(pub, h[:], tx.SigHex)
		if err != nil || !ok {
			return errors.New("invalid signature")
		}
		if isHexAddress(tx.From) {
			addr := wallet.AddressFromPublicKey(pub)
			if addr != tx.From {
				return errors.New("from does not match pubkey address")
			}
		}
	}
	inSum := int64(0)
	// verify inputs exist and belong to From
	for _, in := range tx.Inputs {
		utxo, ok := st.UTXO[makeKey(in.TxID, in.Index)]
		if !ok {
			return fmt.Errorf("input not found: %s:%d", in.TxID, in.Index)
		}
		if utxo.To != tx.From {
			return errors.New("input does not belong to sender")
		}
		inSum += utxo.Amount
	}
	outSum := int64(0)
	for _, out := range tx.Outputs {
		if out.Amount <= 0 {
			return errors.New("output amount must be positive")
		}
		outSum += out.Amount
	}
	if outSum > inSum {
		return errors.New("outputs exceed inputs")
	}
	// Apply: remove inputs, add outputs; update balances convenience index
	for _, in := range tx.Inputs {
		utxo := st.UTXO[makeKey(in.TxID, in.Index)]
		st.Balances[utxo.To] -= utxo.Amount
		delete(st.UTXO, makeKey(in.TxID, in.Index))
	}
	for idx, out := range tx.Outputs {
		st.Balances[out.To] += out.Amount
		st.UTXO[makeKey(tx.ID, idx)] = out
	}
	return nil
}

// selectionCore performs the deterministic, stake-weighted selection using provided inputs only.
// It is lock-free and safe to call from contexts where caller handles synchronization.
func selectionCore(prevHash string, height uint64, stakes map[string]uint64) (validator string, proof string, err error) {
	if len(stakes) == 0 {
		return "", "", errors.New("no validators")
	}
	total := uint64(0)
	keys := make([]string, 0, len(stakes))
	for k, v := range stakes {
		if v > 0 {
			total += v
			keys = append(keys, k)
		}
	}
	if total == 0 {
		return "", "", errors.New("zero total stake")
	}

	// Deterministic seeded RNG based on provided prev hash and height
	seedBytes := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", prevHash, height)))
	seed := int64(binaryToUint64(seedBytes[:8]))
	r := rand.New(rand.NewSource(seed))
	pick := uint64(r.Int63n(int64(total)))
	cum := uint64(0)
	sort.Strings(keys)
	for _, k := range keys {
		s := stakes[k]
		if s == 0 {
			continue
		}
		if pick >= cum && pick < cum+s {
			return k, hex.EncodeToString(seedBytes[:]), nil
		}
		cum += s
	}
	// Fallback
	for _, k := range keys {
		if stakes[k] > 0 {
			return k, hex.EncodeToString(seedBytes[:]), nil
		}
	}
	return "", "", errors.New("selection failed")
}

// PoSSelection selects a validator according to their stake proportional probability.
// We simulate with a deterministic seed per height to be reproducible.
func (bc *Blockchain) PoSSelection(height uint64) (validator string, proof string, err error) {
	// Read required data under read lock, then compute without holding locks
	bc.mu.RLock()
	prev := bc.blocks[len(bc.blocks)-1].Hash
	stakesCopy := make(map[string]uint64, len(bc.stake.Stakes))
	for k, v := range bc.stake.Stakes {
		stakesCopy[k] = v
	}
	bc.mu.RUnlock()
	return selectionCore(prev, height, stakesCopy)
}

// ProposeBlock selects a validator and creates a block from current mempool, applying state changes.
func (bc *Blockchain) ProposeBlock(maxTx int) (*types.Block, error) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	// Determine selection using lock-free core with data gathered under the write lock
	height := uint64(len(bc.blocks))
	prevHash := bc.blocks[len(bc.blocks)-1].Hash
	stakesCopy := make(map[string]uint64, len(bc.stake.Stakes))
	for k, v := range bc.stake.Stakes {
		stakesCopy[k] = v
	}
	validator, proof, err := selectionCore(prevHash, height, stakesCopy)
	if err != nil {
		return nil, err
	}

	// Copy state to apply txs
	st := &State{Balances: map[string]int64{}, UTXO: map[string]types.TxOutput{}}
	for a, b := range bc.state.Balances {
		st.Balances[a] = b
	}
	for k, v := range bc.state.UTXO {
		st.UTXO[k] = v
	}

	// Sort mempool by timestamp then lexical ID for determinism
	sort.Slice(bc.mempool, func(i, j int) bool {
		if bc.mempool[i].Timestamp == bc.mempool[j].Timestamp {
			return bc.mempool[i].ID < bc.mempool[j].ID
		}
		return bc.mempool[i].Timestamp < bc.mempool[j].Timestamp
	})

	chosen := []types.Transaction{}
	applied := 0
	for _, tx := range bc.mempool {
		if maxTx > 0 && applied >= maxTx {
			break
		}
		if err := bc.validateAndApplyTx(st, tx); err == nil {
			chosen = append(chosen, tx)
			applied++
		}
	}

	// Create coinbase (block reward) for the selected validator and apply to state
	reward := BlockReward
	cb := types.Transaction{
		ID:        fmt.Sprintf("coinbase-%d-%d", height, time.Now().UnixNano()),
		From:      "coinbase",
		Inputs:    []types.TxInput{},
		Outputs:   []types.TxOutput{{To: validator, Amount: reward}},
		Timestamp: time.Now().Unix(),
	}
	// Apply reward directly to state (special-case mint)
	st.Balances[validator] += reward
	st.UTXO[makeKey(cb.ID, 0)] = types.TxOutput{To: validator, Amount: reward}

	// Prepend coinbase to block transactions
	txs := make([]types.Transaction, 0, len(chosen)+1)
	txs = append(txs, cb)
	txs = append(txs, chosen...)

	// Build block
	b := types.NewBlock(height, prevHash, txs, validator, proof)

	// Verify and commit block to canonical chain
	if err := bc.validateBlock(b); err != nil {
		return nil, err
	}
	// Commit state and prune mempool used txs
	bc.state = st
	bc.blocks = append(bc.blocks, b)
	bc.pruneMempool(chosen)
	return b, nil
}

// pruneMempool removes included transactions
func (bc *Blockchain) pruneMempool(included []types.Transaction) {
	if len(included) == 0 || len(bc.mempool) == 0 {
		return
	}
	inc := map[string]struct{}{}
	for _, t := range included {
		inc[t.ID] = struct{}{}
	}
	out := bc.mempool[:0]
	for _, t := range bc.mempool {
		if _, ok := inc[t.ID]; !ok {
			out = append(out, t)
		}
	}
	bc.mempool = out
}

// validateBlock checks previous hash linkage and recomputes hash.
func (bc *Blockchain) validateBlock(b *types.Block) error {
	if b.Index != uint64(len(bc.blocks)) {
		return fmt.Errorf("wrong index: %d", b.Index)
	}
	if b.PrevHash != bc.blocks[len(bc.blocks)-1].Hash {
		return errors.New("prev hash mismatch")
	}
	if types.ComputeMerkleRoot(b.Txns) != b.TxRoot {
		return errors.New("txroot mismatch")
	}
	if b.ComputeHash() != b.Hash {
		return errors.New("block hash mismatch")
	}
	// Verify PoS proof matches deterministic seed derived from the block's own prev hash and index.
	seedBytes := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", b.PrevHash, b.Index)))
	expectedProof := hex.EncodeToString(seedBytes[:])
	if expectedProof != b.StakeProof {
		return errors.New("invalid stake proof")
	}
	return nil
}

// AcceptBlock validates an externally received block and applies it to the canonical chain.
// It verifies linkage, hashes, PoS proof, applies coinbase reward, then all txs.
func (bc *Blockchain) AcceptBlock(b *types.Block) error {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	// Basic header checks against our current head
	if b.Index != uint64(len(bc.blocks)) {
		return fmt.Errorf("wrong index: %d", b.Index)
	}
	if b.PrevHash != bc.blocks[len(bc.blocks)-1].Hash {
		return errors.New("prev hash mismatch")
	}
	if types.ComputeMerkleRoot(b.Txns) != b.TxRoot {
		return errors.New("txroot mismatch")
	}
	if b.ComputeHash() != b.Hash {
		return errors.New("block hash mismatch")
	}
	// Verify PoS seed proof
	seedBytes := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", b.PrevHash, b.Index)))
	expectedProof := hex.EncodeToString(seedBytes[:])
	if expectedProof != b.StakeProof {
		return errors.New("invalid stake proof")
	}

	// Prepare a working copy of state
	st := &State{Balances: map[string]int64{}, UTXO: map[string]types.TxOutput{}}
	for a, bal := range bc.state.Balances {
		st.Balances[a] = bal
	}
	for k, v := range bc.state.UTXO {
		st.UTXO[k] = v
	}

	// Apply coinbase if present as first tx: From=="coinbase", no inputs, sum(outputs)==BlockReward
	startIdx := 0
	if len(b.Txns) > 0 {
		cb := b.Txns[0]
		if cb.From == "coinbase" && len(cb.Inputs) == 0 && len(cb.Outputs) > 0 {
			outSum := int64(0)
			for _, o := range cb.Outputs {
				if o.Amount <= 0 {
					return errors.New("invalid coinbase output")
				}
				outSum += o.Amount
			}
			// Allow zero or configured reward; if BlockReward defined, enforce it if >0
			if BlockReward > 0 && outSum != BlockReward {
				return fmt.Errorf("coinbase reward mismatch: %d", outSum)
			}
			for idx, o := range cb.Outputs {
				st.Balances[o.To] += o.Amount
				st.UTXO[makeKey(cb.ID, idx)] = o
			}
			startIdx = 1
		}
	}
	// Apply remaining txs
	for i := startIdx; i < len(b.Txns); i++ {
		if err := bc.validateAndApplyTx(st, b.Txns[i]); err != nil {
			return fmt.Errorf("tx %d invalid: %w", i, err)
		}
	}

	// Commit state and append block
	bc.state = st
	bc.blocks = append(bc.blocks, b)
	// Remove included txs (excluding coinbase) from mempool
	if startIdx < len(b.Txns) {
		bc.pruneMempool(b.Txns[startIdx:])
	}
	return nil
}

// VerifyChain verifies hashes and linkage across the whole chain; returns index of first bad block or -1 when ok.
func (bc *Blockchain) VerifyChain() (int, error) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	for i := 1; i < len(bc.blocks); i++ {
		prev := bc.blocks[i-1]
		cur := bc.blocks[i]
		if cur.PrevHash != prev.Hash {
			return i, fmt.Errorf("link mismatch at %d", i)
		}
		if cur.ComputeHash() != cur.Hash {
			return i, fmt.Errorf("hash mismatch at %d", i)
		}
		if types.ComputeMerkleRoot(cur.Txns) != cur.TxRoot {
			return i, fmt.Errorf("txroot mismatch at %d", i)
		}
	}
	return -1, nil
}

// GetBalance returns the balance of an address.
func (bc *Blockchain) GetBalance(addr string) int64 {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.state.Balances[addr]
}

// GetUTXO returns copy of current UTXO set
type UTXOEntry struct {
	TxID   string
	Index  int
	Output types.TxOutput
}

// ListUTXO returns a slice of UTXOs with parsed keys for convenience.
func (bc *Blockchain) ListUTXO() []UTXOEntry {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	entries := make([]UTXOEntry, 0, len(bc.state.UTXO))
	for k, v := range bc.state.UTXO {
		txid, idx := parseKey(k)
		entries = append(entries, UTXOEntry{TxID: txid, Index: idx, Output: v})
	}
	return entries
}

// UpdateStake sets or updates the stake for a validator.
func (bc *Blockchain) UpdateStake(addr string, amount uint64) {
	bc.mu.Lock()
	bc.stake.Stakes[addr] = amount
	bc.mu.Unlock()
}

// Snapshot returns a JSON-serializable snapshot
type Snapshot struct {
	Blocks []*types.Block `json:"blocks"`
	State  *State         `json:"state"`
	Stake  *StakeState    `json:"stake"`
}

func (bc *Blockchain) Snapshot() *Snapshot {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	blocks := make([]*types.Block, len(bc.blocks))
	for i := range bc.blocks {
		// Deep copy not strictly required for persistence read-only
		blocks[i] = bc.blocks[i]
	}
	st := &State{Balances: map[string]int64{}, UTXO: map[string]types.TxOutput{}}
	for a, b := range bc.state.Balances {
		st.Balances[a] = b
	}
	for k, v := range bc.state.UTXO {
		st.UTXO[k] = v
	}
	sk := &StakeState{Stakes: map[string]uint64{}}
	for a, s := range bc.stake.Stakes {
		sk.Stakes[a] = s
	}
	return &Snapshot{Blocks: blocks, State: st, Stake: sk}
}

// LoadSnapshot replaces in-memory state from snapshot, verifying linkage and hashes.
func (bc *Blockchain) LoadSnapshot(s *Snapshot) error {
	if s == nil || len(s.Blocks) == 0 {
		return errors.New("invalid snapshot")
	}
	// Validate linkage
	for i := 1; i < len(s.Blocks); i++ {
		if s.Blocks[i].PrevHash != s.Blocks[i-1].Hash {
			return fmt.Errorf("snapshot link mismatch at %d", i)
		}
		if s.Blocks[i].ComputeHash() != s.Blocks[i].Hash {
			return fmt.Errorf("snapshot hash mismatch at %d", i)
		}
		if types.ComputeMerkleRoot(s.Blocks[i].Txns) != s.Blocks[i].TxRoot {
			return fmt.Errorf("snapshot txroot mismatch at %d", i)
		}
	}
	bc.mu.Lock()
	defer bc.mu.Unlock()
	bc.blocks = s.Blocks
	bc.state = s.State
	bc.stake = s.Stake
	bc.mempool = nil
	return nil
}

// binaryToUint64 takes first 8 bytes little endian to uint64.
func binaryToUint64(b []byte) uint64 {
	var v uint64
	for i := 0; i < 8 && i < len(b); i++ {
		v |= uint64(b[i]) << (8 * i)
	}
	return v
}

func makeKey(txid string, index int) string { return fmt.Sprintf("%s:%d", txid, index) }
func parseKey(key string) (string, int) {
	i := strings.LastIndex(key, ":")
	if i < 0 {
		return key, 0
	}
	txid := key[:i]
	n, _ := strconv.Atoi(key[i+1:])
	return txid, n
}

// isHexAddress returns true if s is 40 hex characters (our simple address format).
func isHexAddress(s string) bool {
	if len(s) != 40 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
