package p2p

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"

	"Assignment_2_Repo/internal/chain"
	"Assignment_2_Repo/internal/types"
)

// Node is a minimal HTTP-based P2P peer for broadcasting txs and blocks and syncing chains.
type Node struct {
    mu    sync.RWMutex
    self  string         // http listen address, e.g., ":8080"
    peers map[string]struct{}
    bc    *chain.Blockchain
}

func NewNode(listen string, bc *chain.Blockchain) *Node {
    return &Node{self: listen, peers: map[string]struct{}{}, bc: bc}
}

func (n *Node) AddPeer(addr string) { n.mu.Lock(); n.peers[addr] = struct{}{}; n.mu.Unlock() }
func (n *Node) Peers() []string { n.mu.RLock(); defer n.mu.RUnlock(); out := make([]string,0,len(n.peers)); for p := range n.peers { out = append(out,p) }; sort.Strings(out); return out }

// Serve starts HTTP endpoints:
// - POST /tx    body: Transaction
// - POST /block body: Block
// - GET  /chain returns chain.Snapshot
// - POST /peers body: {addrs: []string}
func (n *Node) Serve() error {
    mux := http.NewServeMux()
    mux.HandleFunc("/tx", n.handleTx)
    mux.HandleFunc("/block", n.handleBlock)
    mux.HandleFunc("/chain", n.handleChain)
    mux.HandleFunc("/peers", n.handlePeers)
    return http.ListenAndServe(n.self, mux)
}

func (n *Node) handleTx(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
    var tx types.Transaction
    if err := json.NewDecoder(r.Body).Decode(&tx); err != nil { http.Error(w, err.Error(), http.StatusBadRequest); return }
    if err := n.bc.SubmitTransaction(tx); err != nil { http.Error(w, err.Error(), http.StatusBadRequest); return }
    _ = json.NewEncoder(w).Encode(map[string]string{"status":"ok","id":tx.ID})
}

func (n *Node) handleBlock(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
    var b types.Block
    if err := json.NewDecoder(r.Body).Decode(&b); err != nil { http.Error(w, err.Error(), http.StatusBadRequest); return }
    if err := n.bc.AcceptBlock(&b); err != nil { http.Error(w, err.Error(), http.StatusBadRequest); return }
    _ = json.NewEncoder(w).Encode(map[string]string{"status":"accepted","index":fmt.Sprint(b.Index)})
}

func (n *Node) handleChain(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
    _ = json.NewEncoder(w).Encode(n.bc.Snapshot())
}

func (n *Node) handlePeers(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        _ = json.NewEncoder(w).Encode(map[string][]string{"peers": n.Peers()})
    case http.MethodPost:
        var body struct{ Addrs []string `json:"addrs"` }
        if err := json.NewDecoder(r.Body).Decode(&body); err != nil { http.Error(w, err.Error(), http.StatusBadRequest); return }
        for _, a := range body.Addrs { n.AddPeer(a) }
        _ = json.NewEncoder(w).Encode(map[string]string{"status":"ok"})
    default:
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
    }
}

// BroadcastTx sends a transaction to all peers.
func (n *Node) BroadcastTx(tx types.Transaction) {
    payload, _ := json.Marshal(tx)
    for _, p := range n.Peers() { http.Post("http://"+p+"/tx", "application/json", bytes.NewReader(payload)) }
}

// BroadcastBlock sends a block to all peers.
func (n *Node) BroadcastBlock(b *types.Block) {
    payload, _ := json.Marshal(b)
    for _, p := range n.Peers() { http.Post("http://"+p+"/block", "application/json", bytes.NewReader(payload)) }
}

// Sync pulls chains from peers and adopts the longest valid snapshot.
func (n *Node) Sync() error {
    best := n.bc.Snapshot()
    for _, p := range n.Peers() {
        url := "http://"+p+"/chain"
        resp, err := http.Get(url)
        if err != nil { continue }
        body, _ := io.ReadAll(resp.Body); _ = resp.Body.Close()
        var snap chain.Snapshot
        if err := json.Unmarshal(body, &snap); err != nil { continue }
        if len(snap.Blocks) > len(best.Blocks) {
            // Try to apply to a temp chain to validate
            tmp := chain.NewBlockchain(map[string]int64{}, map[string]uint64{})
            if err := tmp.LoadSnapshot(&snap); err != nil { continue }
            if _, err := tmp.VerifyChain(); err != nil { continue }
            // Accept
            _ = n.bc.LoadSnapshot(&snap)
            best = &snap
        }
    }
    return nil
}
