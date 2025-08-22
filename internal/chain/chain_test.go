package chain_test

import (
	"fmt"
	"path/filepath"
	"testing"

	"Assignment_2_Repo/internal/chain"
	"Assignment_2_Repo/internal/persist"
	"Assignment_2_Repo/internal/types"
	"Assignment_2_Repo/internal/wallet"
)

func newTestChain() *chain.Blockchain {
	balances := map[string]int64{"a": 100, "b": 50}
	stakes := map[string]uint64{"a": 80, "b": 20}
	return chain.NewBlockchain(balances, stakes)
}

func TestMerkleRootChangesOnTxMutation(t *testing.T) {
	tx1 := types.Transaction{ID: "1", From: "a", Inputs: []types.TxInput{{TxID: "genesis-a", Index: 0}}, Outputs: []types.TxOutput{{To: "b", Amount: 1}}}
	tx2 := types.Transaction{ID: "2", From: "b", Inputs: []types.TxInput{{TxID: "genesis-b", Index: 0}}, Outputs: []types.TxOutput{{To: "a", Amount: 2}}}
	root1 := types.ComputeMerkleRoot([]types.Transaction{tx1, tx2})
	tx2.Outputs[0].Amount = 3
	root2 := types.ComputeMerkleRoot([]types.Transaction{tx1, tx2})
	if root1 == root2 {
		t.Fatal("merkle root should change when tx changes")
	}
}

func TestPoSSelectionDeterministic(t *testing.T) {
	bc := newTestChain()
	v1, p1, err := bc.PoSSelection(1)
	if err != nil {
		t.Fatal(err)
	}
	v2, p2, err := bc.PoSSelection(1)
	if err != nil {
		t.Fatal(err)
	}
	if v1 != v2 || p1 != p2 {
		t.Fatal("selection must be deterministic for same height and prev hash")
	}
}

func TestDoubleSpendPreventionWithUTXO(t *testing.T) {
	bc := newTestChain()
	// Find a genesis UTXO for 'a'
	utxos := bc.ListUTXO()
	var txid string
	var idx int
	var amount int64
	found := false
	for _, e := range utxos {
		if e.Output.To == "a" {
			txid = e.TxID
			idx = e.Index
			amount = e.Output.Amount
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no utxo for a")
	}
	// Spend that input to b (partial spend allowed if outputs < input; remainder omitted for simplicity)
	tx1 := types.Transaction{ID: "t1", From: "a", Inputs: []types.TxInput{{TxID: txid, Index: idx}}, Outputs: []types.TxOutput{{To: "b", Amount: amount}}}
	if err := bc.SubmitTransaction(tx1); err != nil {
		t.Fatal(err)
	}
	// Attempt to double-spend same input in another pending tx
	tx2 := types.Transaction{ID: "t2", From: "a", Inputs: []types.TxInput{{TxID: txid, Index: idx}}, Outputs: []types.TxOutput{{To: "b", Amount: amount}}}
	if err := bc.SubmitTransaction(tx2); err == nil {
		t.Fatal("expected rejection due to conflicting pending spend")
	}
}

func TestSnapshotPersistence(t *testing.T) {
	bc := newTestChain()
	// Add one tx and propose a block
	// Build a tx spending one of 'a' UTXOs to 'b'
	utxos := bc.ListUTXO()
	var txid string
	var idx int
	var amount int64
	found := false
	for _, e := range utxos {
		if e.Output.To == "a" {
			txid = e.TxID
			idx = e.Index
			amount = e.Output.Amount
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no utxo for a")
	}
	tx := types.Transaction{ID: "x", From: "a", Inputs: []types.TxInput{{TxID: txid, Index: idx}}, Outputs: []types.TxOutput{{To: "b", Amount: amount}}}
	if err := bc.SubmitTransaction(tx); err != nil {
		t.Fatal(err)
	}
	if _, err := bc.ProposeBlock(100); err != nil {
		t.Fatal(err)
	}
	// Save snapshot
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")
	if err := persist.Save(path, bc.Snapshot()); err != nil {
		t.Fatal(err)
	}
	// Load snapshot
	s, err := persist.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	bc2 := chain.NewBlockchain(map[string]int64{}, map[string]uint64{})
	if err := bc2.LoadSnapshot(s); err != nil {
		t.Fatal(err)
	}
	if _, err := bc2.VerifyChain(); err != nil {
		t.Fatalf("loaded chain invalid: %v", err)
	}
}

func TestSignedTransactionVerification(t *testing.T) {
	bc := newTestChain()
	// Generate a key and map its address to an existing funded account by transferring
	priv, _, addr, err := wallet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// Spend one UTXO from 'a' to the new addr with a signed tx using 'a' as logical owner (no signature expected for this legacy path)
	utxos := bc.ListUTXO()
	var txid string
	var idx int
	var amount int64
	for _, e := range utxos {
		if e.Output.To == "a" {
			txid = e.TxID
			idx = e.Index
			amount = e.Output.Amount
			break
		}
	}
	tx1 := types.Transaction{ID: "fund", From: "a", Inputs: []types.TxInput{{TxID: txid, Index: idx}}, Outputs: []types.TxOutput{{To: addr, Amount: amount}}}
	if err := bc.SubmitTransaction(tx1); err != nil {
		t.Fatal(err)
	}
	if _, err := bc.ProposeBlock(100); err != nil {
		t.Fatal(err)
	}
	// Now build a signed tx spending from addr back to 'b'
	utxos2 := bc.ListUTXO()
	var txid2 string
	var idx2 int
	var amt2 int64
	for _, e := range utxos2 {
		if e.Output.To == addr {
			txid2 = e.TxID
			idx2 = e.Index
			amt2 = e.Output.Amount
			break
		}
	}
	pk, err := wallet.ParsePrivateKeyHex(priv)
	if err != nil {
		t.Fatal(err)
	}
	tx2 := types.Transaction{ID: "signed", From: addr, Inputs: []types.TxInput{{TxID: txid2, Index: idx2}}, Outputs: []types.TxOutput{{To: "b", Amount: amt2}}}
	h := tx2.SignableHash()
	sig, err := wallet.SignHash(pk, h[:])
	if err != nil {
		t.Fatal(err)
	}
	tx2.SigHex = sig
	tx2.PubKeyHex = fmt.Sprintf("%x", wallet.MarshalPubkey(&pk.PublicKey))
	if err := bc.SubmitTransaction(tx2); err != nil {
		t.Fatalf("signed tx rejected: %v", err)
	}
}

// TestMultipleTransactionsDifferentUTXOsInSameBlock verifies that two transactions
// from the same sender using different UTXOs can both be accepted into the mempool
// and included in a single proposed block without being flagged as conflicting.
func TestMultipleTransactionsDifferentUTXOsInSameBlock(t *testing.T) {
	// Give 'a' enough balance so NewBlockchain splits it into multiple UTXOs (chunk=100)
	// 250 -> UTXOs: 100, 100, 50
	bc := chain.NewBlockchain(map[string]int64{"a": 250, "b": 0}, map[string]uint64{"a": 1})
	// Collect two distinct UTXOs for 'a'
	utxos := bc.ListUTXO()
	inputs := make([]types.TxInput, 0, 2)
	counts := 0
	for _, e := range utxos {
		if e.Output.To == "a" {
			inputs = append(inputs, types.TxInput{TxID: e.TxID, Index: e.Index})
			counts++
			if counts == 2 {
				break
			}
		}
	}
	if len(inputs) < 2 {
		t.Fatalf("expected at least 2 UTXOs for 'a', got %d", len(inputs))
	}
	// Build two separate txs each spending one UTXO of 100 to 'b'
	tx1 := types.Transaction{ID: "m1", From: "a", Inputs: []types.TxInput{inputs[0]}, Outputs: []types.TxOutput{{To: "b", Amount: 100}}}
	tx2 := types.Transaction{ID: "m2", From: "a", Inputs: []types.TxInput{inputs[1]}, Outputs: []types.TxOutput{{To: "b", Amount: 100}}}
	if err := bc.SubmitTransaction(tx1); err != nil {
		t.Fatalf("tx1 rejected: %v", err)
	}
	if err := bc.SubmitTransaction(tx2); err != nil {
		t.Fatalf("tx2 rejected: %v", err)
	}
	// Propose a block with both txs
	b, err := bc.ProposeBlock(100)
	if err != nil {
		t.Fatalf("propose failed: %v", err)
	}
	// Expect coinbase + 2 txs
	if got, want := len(b.Txns), 3; got != want {
		t.Fatalf("expected %d txs in block (including coinbase), got %d", want, got)
	}
	// Check balances reflect transfers: b should receive 200 (+ any prior), a should be reduced by 200
	if bc.GetBalance("b") < 200 {
		t.Fatalf("recipient balance < 200, got %d", bc.GetBalance("b"))
	}
}
