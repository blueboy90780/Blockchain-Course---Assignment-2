package types

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// TxInput references an unspent output from a previous transaction.
type TxInput struct {
    TxID  string `json:"txId"`
    Index int    `json:"index"`
}

// TxOutput creates a new spendable output to an address.
type TxOutput struct {
    To     string `json:"to"`
    Amount int64  `json:"amount"`
}

// Transaction now follows a simplified UTXO model: a set of inputs and outputs.
// For this educational PoS chain, we omit signatures and scripts; instead, we enforce
// that all inputs must have been addressed to the declared From address.
type Transaction struct {
    ID        string     `json:"id"`
    From      string     `json:"from"`       // logical owner of inputs (simulated signature)
    Inputs    []TxInput  `json:"inputs"`
    Outputs   []TxOutput `json:"outputs"`
    Timestamp int64      `json:"timestamp"`
    // Crypto fields
    PubKeyHex string     `json:"pubKeyHex,omitempty"` // uncompressed hex public key of signer
    SigHex    string     `json:"sigHex,omitempty"`     // signature over SignableHash
}

// Hash returns the SHA-256 hash of the JSON-serialized transaction.
func (tx *Transaction) Hash() string {
    b, _ := json.Marshal(tx)
    sum := sha256.Sum256(b)
    return hex.EncodeToString(sum[:])
}

// SignableHash returns the SHA-256 of a canonical subset of the transaction fields
// that are intended to be signed: From, Inputs, Outputs, and Timestamp. It excludes
// ID, PubKeyHex, and SigHex to avoid circular dependencies.
func (tx *Transaction) SignableHash() [32]byte {
    payload := struct {
        From      string     `json:"from"`
        Inputs    []TxInput  `json:"inputs"`
        Outputs   []TxOutput `json:"outputs"`
        Timestamp int64      `json:"timestamp"`
    }{From: tx.From, Inputs: tx.Inputs, Outputs: tx.Outputs, Timestamp: tx.Timestamp}
    b, _ := json.Marshal(payload)
    return sha256.Sum256(b)
}

// Block encapsulates a batch of transactions linked to the previous block by hash.
type Block struct {
    Index        uint64         `json:"index"`
    Timestamp    int64          `json:"timestamp"`
    PrevHash     string         `json:"prevHash"`
    Txns         []Transaction  `json:"txns"`
    TxRoot       string         `json:"txRoot"`       // Merkle root over Txns for integrity
    Validator    string         `json:"validator"`    // address of the validator who proposed this block
    StakeProof   string         `json:"stakeProof"`   // deterministic selection proof (e.g., VRF-like placeholder)
    Hash         string         `json:"hash"`
}

// NewBlock constructs a block with the provided params and computes its TxRoot and Hash.
func NewBlock(index uint64, prevHash string, txns []Transaction, validator string, stakeProof string) *Block {
    b := &Block{
        Index:     index,
        Timestamp: time.Now().Unix(),
        PrevHash:  prevHash,
        Txns:      txns,
        Validator: validator,
        StakeProof: stakeProof,
    }
    b.TxRoot = ComputeMerkleRoot(txns)
    b.Hash = b.ComputeHash()
    return b
}

// ComputeHash calculates the block hash over all critical fields.
func (b *Block) ComputeHash() string {
    payload := struct {
        Index     uint64        `json:"index"`
        Timestamp int64         `json:"timestamp"`
        PrevHash  string        `json:"prevHash"`
        TxRoot    string        `json:"txRoot"`
        Validator string        `json:"validator"`
        StakeProof string       `json:"stakeProof"`
    }{
        Index: b.Index,
        Timestamp: b.Timestamp,
        PrevHash: b.PrevHash,
        TxRoot: b.TxRoot,
        Validator: b.Validator,
        StakeProof: b.StakeProof,
    }
    data, _ := json.Marshal(payload)
    sum := sha256.Sum256(data)
    return hex.EncodeToString(sum[:])
}

// ComputeMerkleRoot computes a simple binary Merkle root of transaction hashes.
// For odd nodes, the last hash is duplicated (Bitcoin-style) for pairing.
func ComputeMerkleRoot(txns []Transaction) string {
    if len(txns) == 0 {
        empty := sha256.Sum256([]byte(""))
        return hex.EncodeToString(empty[:])
    }
    // Build initial level from transaction hashes
    level := make([][]byte, 0, len(txns))
    for i := range txns {
        h := txns[i].Hash()
        b, _ := hex.DecodeString(h)
        level = append(level, b)
    }
    // Reduce until one root remains
    for len(level) > 1 {
        next := make([][]byte, 0, (len(level)+1)/2)
        for i := 0; i < len(level); i += 2 {
            if i+1 < len(level) {
                combined := append(level[i], level[i+1]...)
                sum := sha256.Sum256(combined)
                next = append(next, sum[:])
            } else {
                // duplicate last when odd
                combined := append(level[i], level[i]...)
                sum := sha256.Sum256(combined)
                next = append(next, sum[:])
            }
        }
        level = next
    }
    return hex.EncodeToString(level[0])
}
