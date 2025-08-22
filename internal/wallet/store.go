package wallet

import (
	"encoding/json"
	"errors"
	"os"
)

// Entry holds keys for an address (alias or hex address string used in chain state).
type Entry struct {
	Address    string `json:"address"`
	PubKeyHex  string `json:"pubKeyHex"`
	PrivKeyHex string `json:"privKeyHex"`
}

// Store maps address -> Entry.
type Store map[string]Entry

// LoadStore loads a wallet store from path if present; returns empty store if file missing.
func LoadStore(path string) (Store, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Store{}, nil
		}
		return nil, err
	}
	var s Store
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return s, nil
}

// SaveStore writes the store to path with 0600 permissions (best effort on Windows).
func SaveStore(path string, s Store) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}
