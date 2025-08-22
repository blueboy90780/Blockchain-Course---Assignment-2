package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"Assignment_2_Repo/internal/chain"
	"Assignment_2_Repo/internal/p2p"
	"Assignment_2_Repo/internal/persist"
	"Assignment_2_Repo/internal/types"
	"Assignment_2_Repo/internal/wallet"
)

// Simple interactive CLI to meet the assignment requirements.
func main() {
	dataDir := flag.String("datadir", ".", "data directory for persistence")
	flag.Parse()

	// Attempt to load state, else create a new chain with demo balances and stakes
	snapshotPath := filepath.Join(*dataDir, "pos_chain.json")
	var bc *chain.Blockchain
	if s, err := persist.Load(snapshotPath); err == nil {
		// load
		bc = chain.NewBlockchain(map[string]int64{}, map[string]uint64{})
		if err := bc.LoadSnapshot(s); err != nil {
			fmt.Println("Failed to load snapshot, starting new chain:", err)
			bc = defaultChain()
		} else {
			fmt.Println("Loaded blockchain from", snapshotPath)
		}
	} else {
		bc = defaultChain()
	}

	// Initialize optional P2P node holder (constructed on demand)
	var node *p2p.Node
	walletPath := filepath.Join(*dataDir, "wallets.json")

	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Simple PoS Blockchain CLI. Type 'help' for commands.")
	for {
		fmt.Print("> ")
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		cmd := strings.ToLower(parts[0])
		switch cmd {
		case "help":
			printHelp()
		case "balances":
			printBalances(bc)
		case "serve":
			// serve <host:port>
			if len(parts) != 2 {
				fmt.Println("usage: serve <host:port>")
				continue
			}
			addr := parts[1]
			// Recreate node to bind address but keep peers if previously set
			if node == nil {
				node = p2p.NewNode(addr, bc)
			} else {
				oldPeers := node.Peers()
				node = p2p.NewNode(addr, bc)
				for _, p := range oldPeers {
					node.AddPeer(p)
				}
			}
			go func() {
				if err := node.Serve(); err != nil {
					fmt.Println("server error:", err)
				}
			}()
			fmt.Println("serving on", addr)
		case "peer":
			// peer add <host:port> | peer list
			if len(parts) < 2 {
				fmt.Println("usage: peer add <addr> | peer list")
				continue
			}
			action := strings.ToLower(parts[1])
			switch action {
			case "add":
				if len(parts) != 3 {
					fmt.Println("usage: peer add <host:port>")
					continue
				}
				if node == nil {
					node = p2p.NewNode(":0", bc)
				}
				node.AddPeer(parts[2])
				fmt.Println("added peer", parts[2])
			case "list":
				if node == nil {
					fmt.Println("no peers")
					continue
				}
				for _, p := range node.Peers() {
					fmt.Println(p)
				}
			default:
				fmt.Println("usage: peer add <addr> | peer list")
			}
		case "sync":
			if node == nil {
				fmt.Println("not serving; add peers first with 'peer add'")
				continue
			}
			if err := node.Sync(); err != nil {
				fmt.Println("sync error:", err)
			} else {
				fmt.Println("sync complete")
			}
		case "stake":
			if len(parts) != 3 {
				fmt.Println("usage: stake <address> <amount>")
				continue
			}
			amt, err := strconv.ParseUint(parts[2], 10, 64)
			if err != nil {
				fmt.Println("invalid amount")
				continue
			}
			bc.UpdateStake(parts[1], amt)
			fmt.Println("updated stake for", parts[1], "=", amt)
		case "tx":
			// tx <from> <to> <amount> [privHex]
			if len(parts) != 4 && len(parts) != 5 {
				fmt.Println("usage: tx <from> <to> <amount> [privHex]")
				continue
			}
			amt, err := strconv.ParseInt(parts[3], 10, 64)
			if err != nil || amt <= 0 {
				fmt.Println("invalid amount")
				continue
			}
			from := parts[1]
			to := parts[2]
			// Coin selection: gather sender UTXOs until amount is covered, skipping inputs reserved by mempool
			reserved := map[string]struct{}{}
			for _, t := range bc.Mempool() {
				for _, in := range t.Inputs {
					reserved[fmt.Sprintf("%s:%d", in.TxID, in.Index)] = struct{}{}
				}
			}
			utxos := bc.ListUTXO()
			inputs := []types.TxInput{}
			gathered := int64(0)
			for _, e := range utxos {
				if e.Output.To != from {
					continue
				}
				key := fmt.Sprintf("%s:%d", e.TxID, e.Index)
				if _, used := reserved[key]; used {
					continue
				}
				inputs = append(inputs, types.TxInput{TxID: e.TxID, Index: e.Index})
				gathered += e.Output.Amount
				if gathered >= amt {
					break
				}
			}
			if gathered < amt {
				fmt.Println("insufficient UTXO to cover amount")
				continue
			}
			outputs := []types.TxOutput{{To: to, Amount: amt}}
			change := gathered - amt
			if change > 0 {
				outputs = append(outputs, types.TxOutput{To: from, Amount: change})
			}
			tx := types.Transaction{ID: fmt.Sprintf("%s-%s-%d-%d", from, to, amt, time.Now().UnixNano()), From: from, Inputs: inputs, Outputs: outputs, Timestamp: time.Now().Unix()}
			// If no privHex provided, try to auto-sign using wallets.json for From (alias or address)
			if len(parts) == 5 || len(parts) == 4 {
				var privHex string
				if len(parts) == 5 {
					privHex = parts[4]
				} else {
					store, _ := wallet.LoadStore(walletPath)
					if w, ok := store[from]; ok {
						privHex = w.PrivKeyHex
					}
				}
				if privHex != "" {
					priv, err := wallet.ParsePrivateKeyHex(privHex)
					if err != nil {
						fmt.Println("bad private key:", err)
						continue
					}
					h := tx.SignableHash()
					sig, err := wallet.SignHash(priv, h[:])
					if err != nil {
						fmt.Println("sign error:", err)
						continue
					}
					tx.SigHex = sig
					tx.PubKeyHex = fmt.Sprintf("%x", wallet.MarshalPubkey(&priv.PublicKey))
				}
			}
			if err := bc.SubmitTransaction(tx); err != nil {
				fmt.Println("tx rejected:", err)
				continue
			}
			fmt.Println("tx accepted:", tx.ID)
			if node != nil {
				node.BroadcastTx(tx)
			}
		case "keygen":
			// Generate keypairs for all existing addresses in current balances
			s := bc.Snapshot()
			store, _ := wallet.LoadStore(walletPath)
			created := 0
			for addr := range s.State.Balances {
				if _, exists := store[addr]; exists {
					continue
				}
				priv, pub, addr2, err := wallet.GenerateKey()
				if err != nil {
					fmt.Println("keygen error:", err)
					continue
				}
				// Ensure mapping corresponds to the loop address; warn if mismatch
				if addr2 != addr {
					// Still store under requested address label for user convenience
				}
				store[addr] = wallet.Entry{Address: addr, PubKeyHex: pub, PrivKeyHex: priv}
				// Print out the generated keypair for this user
				fmt.Println("---------------------------")
				fmt.Println("user:", addr)
				fmt.Println("address:", addr)
				fmt.Println("pubkey:", pub)
				fmt.Println("privkey:", priv)
				created++
			}
			if created == 0 {
				fmt.Println("no new users without keys; nothing generated")
			}
			if err := wallet.SaveStore(walletPath, store); err != nil {
				fmt.Println("save wallets error:", err)
			} else {
				fmt.Printf("wallets saved to %s (new: %d)\n", walletPath, created)
			}
		case "propose":
			b, err := bc.ProposeBlock(1000)
			if err != nil {
				fmt.Println("proposal failed:", err)
				continue
			}
			fmt.Printf("sealed block %d by %s with %d txs, hash=%s\n", b.Index, b.Validator, len(b.Txns), b.Hash[:16])
			if node != nil {
				node.BroadcastBlock(b)
			}
		case "chain":
			printChain(bc)
		case "verify":
			idx, err := bc.VerifyChain()
			if err != nil {
				fmt.Println("chain invalid at", idx, ":", err)
			} else {
				fmt.Println("chain valid")
			}
		case "tamper":
			// tamper <index>
			if len(parts) != 2 {
				fmt.Println("usage: tamper <index>")
				continue
			}
			i, _ := strconv.Atoi(parts[1])
			if err := tamperBlock(bc, i); err != nil {
				fmt.Println("tamper failed:", err)
			} else {
				fmt.Println("tampered block", i)
			}
		case "save":
			s := bc.Snapshot()
			if err := persist.Save(snapshotPath, s); err != nil {
				fmt.Println("save error:", err)
			} else {
				fmt.Println("saved to", snapshotPath)
			}
		case "load":
			if s, err := persist.Load(snapshotPath); err != nil {
				fmt.Println("load error:", err)
			} else if err := bc.LoadSnapshot(s); err != nil {
				fmt.Println("apply error:", err)
			} else {
				fmt.Println("loaded")
			}
		case "export":
			// export prints JSON snapshot to stdout
			s := bc.Snapshot()
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(s)
		case "quit", "exit":
			fmt.Println("bye")
			return
		default:
			fmt.Println("unknown command; type 'help'")
		}
	}
}

func defaultChain() *chain.Blockchain {
	// Demo initial state: accounts and stakes
	balances := map[string]int64{
		"alice": 1000,
		"bob":   1000,
		"carol": 1000,
	}
	stakes := map[string]uint64{
		"alice": 60,
		"bob":   30,
		"carol": 10,
	}
	return chain.NewBlockchain(balances, stakes)
}

func printHelp() {
	fmt.Println("commands:")
	fmt.Println("  help                                   - show this help")
	fmt.Println("  balances                               - list balances")
	fmt.Println("  serve <host:port>                      - start HTTP node, e.g., 127.0.0.1:8080")
	fmt.Println("  peer add <addr> | peer list            - manage peers")
	fmt.Println("  sync                                   - fetch and adopt the longest valid chain from peers")
	fmt.Println("  stake <address> <amount>               - set validator stake")
	fmt.Println("  keygen                                 - generate a new wallet (address, pubkey, privkey)")
	fmt.Println("  tx <from> <to> <amount> [privHex]      - submit a (signed if privHex provided) transaction")
	fmt.Println("  propose                                - run PoS selection and seal a block")
	fmt.Println("  chain                                  - show chain summary")
	fmt.Println("  verify                                 - verify chain linkage and hashes")
	fmt.Println("  tamper <index>                         - tamper with block data to demo immutability break")
	fmt.Println("  save | load                            - persist or restore blockchain state")
	fmt.Println("  export                                 - print JSON snapshot to stdout")
	fmt.Println("  quit                                   - exit")
}

func printBalances(bc *chain.Blockchain) {
	// Probe balances by exporting snapshot
	s := bc.Snapshot()
	// Sort display
	type kv struct {
		K string
		V int64
	}
	list := make([]kv, 0, len(s.State.Balances))
	for k, v := range s.State.Balances {
		list = append(list, kv{k, v})
	}
	// simple bubble sort due to tiny size
	for i := 0; i < len(list); i++ {
		for j := i + 1; j < len(list); j++ {
			if list[j].K < list[i].K {
				list[i], list[j] = list[j], list[i]
			}
		}
	}
	for _, it := range list {
		fmt.Printf("%s: %d\n", it.K, it.V)
	}
}

func printChain(bc *chain.Blockchain) {
	blocks := bc.Blocks()
	for _, b := range blocks {
		fmt.Printf("[%d] t=%d prev=%s.. hash=%s.. tx=%d validator=%s\n", b.Index, b.Timestamp, short(b.PrevHash), short(b.Hash), len(b.Txns), b.Validator)
	}
}

func short(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}

// tamperBlock intentionally mutates a block's transaction data to break hashes.
func tamperBlock(bc *chain.Blockchain, index int) error {
	if index <= 0 {
		return errors.New("cannot tamper genesis or negative index")
	}
	blocks := bc.Blocks() // returns pointers to actual blocks
	if index >= len(blocks) {
		return fmt.Errorf("index out of range; chain length=%d", len(blocks))
	}
	// Mutate in place without recomputing roots/hashes so verification will fail
	if len(blocks[index].Txns) == 0 {
		// Insert a fake tx with a tiny output to self to break Merkle root
		blocks[index].Txns = append(blocks[index].Txns, types.Transaction{
			ID:        fmt.Sprintf("tampered-%d", time.Now().UnixNano()),
			From:      "alice",
			Inputs:    []types.TxInput{},
			Outputs:   []types.TxOutput{{To: "alice", Amount: 1}},
			Timestamp: time.Now().Unix(),
		})
	} else {
		if len(blocks[index].Txns[0].Outputs) == 0 {
			blocks[index].Txns[0].Outputs = append(blocks[index].Txns[0].Outputs, types.TxOutput{To: "alice", Amount: 1})
		} else {
			blocks[index].Txns[0].Outputs[0].Amount += 1
		}
	}
	// Do not update TxRoot or Hash intentionally
	return nil
}
