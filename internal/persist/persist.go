package persist

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"Assignment_2_Repo/internal/chain"
)

// Save writes the blockchain snapshot to the given path as JSON.
func Save(path string, s *chain.Snapshot) error {
    if s == nil { return errors.New("nil snapshot") }
    if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { return err }
    f, err := os.Create(path)
    if err != nil { return err }
    defer f.Close()
    enc := json.NewEncoder(f)
    enc.SetIndent("", "  ")
    return enc.Encode(s)
}

// Load reads a snapshot from JSON file.
func Load(path string) (*chain.Snapshot, error) {
    f, err := os.Open(path)
    if err != nil { return nil, err }
    defer f.Close()
    dec := json.NewDecoder(f)
    var s chain.Snapshot
    if err := dec.Decode(&s); err != nil { return nil, err }
    return &s, nil
}
