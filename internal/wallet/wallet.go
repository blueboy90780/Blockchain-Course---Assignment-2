package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
)

// GenerateKey creates a new ECDSA P-256 keypair and returns private key hex, public key hex, and address string.
// Address is the first 20 bytes of SHA-256(pubkey uncompressed) hex-encoded.
func GenerateKey() (privHex, pubHex, address string, err error) {
    priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil { return "", "", "", err }
    privHex = PrivateKeyToHex(priv)
    pubBytes := MarshalPubkey(&priv.PublicKey)
    pubHex = hex.EncodeToString(pubBytes)
    addr := AddressFromPubBytes(pubBytes)
    return privHex, pubHex, addr, nil
}

// PrivateKeyToHex encodes the private scalar D as hex.
func PrivateKeyToHex(k *ecdsa.PrivateKey) string { return hex.EncodeToString(k.D.Bytes()) }

// ParsePrivateKeyHex parses a hex-encoded big-int D onto a P-256 curve to make an ECDSA key.
func ParsePrivateKeyHex(privHex string) (*ecdsa.PrivateKey, error) {
    dBytes, err := hex.DecodeString(privHex)
    if err != nil { return nil, err }
    curve := elliptic.P256()
    d := new(big.Int).SetBytes(dBytes)
    if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 { return nil, errors.New("invalid private key") }
    x, y := curve.ScalarBaseMult(d.Bytes())
    return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}, nil
}

// MarshalPubkey returns uncompressed pubkey bytes: 0x04 || X || Y.
func MarshalPubkey(pk *ecdsa.PublicKey) []byte {
    curve := pk.Curve
    byteLen := (curve.Params().BitSize + 7) / 8
    x := pk.X.Bytes(); y := pk.Y.Bytes()
    xb := make([]byte, byteLen); copy(xb[byteLen-len(x):], x)
    yb := make([]byte, byteLen); copy(yb[byteLen-len(y):], y)
    out := make([]byte, 1+2*byteLen)
    out[0] = 0x04
    copy(out[1:1+byteLen], xb)
    copy(out[1+byteLen:], yb)
    return out
}

// UnmarshalPubkey decodes uncompressed pubkey bytes into an ECDSA public key.
func UnmarshalPubkey(b []byte) (*ecdsa.PublicKey, error) {
    if len(b) == 0 || b[0] != 0x04 { return nil, errors.New("unsupported pubkey format") }
    curve := elliptic.P256()
    byteLen := (curve.Params().BitSize + 7) / 8
    if len(b) != 1+2*byteLen { return nil, errors.New("bad pubkey length") }
    x := new(big.Int).SetBytes(b[1 : 1+byteLen])
    y := new(big.Int).SetBytes(b[1+byteLen:])
    if !curve.IsOnCurve(x, y) { return nil, errors.New("pubkey not on curve") }
    return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// AddressFromPubBytes computes the address string from uncompressed pubkey bytes.
func AddressFromPubBytes(pub []byte) string {
    h := sha256.Sum256(pub)
    // first 20 bytes
    return hex.EncodeToString(h[:20])
}

// AddressFromPublicKey computes the address string from an ECDSA public key.
func AddressFromPublicKey(pk *ecdsa.PublicKey) string { return AddressFromPubBytes(MarshalPubkey(pk)) }

// SignHash signs a 32-byte hash with the private key and returns r||s hex.
func SignHash(priv *ecdsa.PrivateKey, hash32 []byte) (sigHex string, err error) {
    if len(hash32) != 32 { return "", errors.New("hash must be 32 bytes") }
    r, s, err := ecdsa.Sign(rand.Reader, priv, hash32)
    if err != nil { return "", err }
    rb := r.Bytes(); sb := s.Bytes()
    // fixed-length encoding per curve size
    size := (priv.Curve.Params().BitSize + 7) / 8
    out := make([]byte, 2*size)
    copy(out[size-len(rb):size], rb)
    copy(out[2*size-len(sb):], sb)
    return hex.EncodeToString(out), nil
}

// VerifyHash verifies r||s hex against the hash and public key.
func VerifyHash(pub *ecdsa.PublicKey, hash32 []byte, sigHex string) (bool, error) {
    if len(hash32) != 32 { return false, errors.New("hash must be 32 bytes") }
    b, err := hex.DecodeString(sigHex)
    if err != nil { return false, err }
    size := (pub.Curve.Params().BitSize + 7) / 8
    if len(b) != 2*size { return false, errors.New("bad signature length") }
    r := new(big.Int).SetBytes(b[:size])
    s := new(big.Int).SetBytes(b[size:])
    return ecdsa.Verify(pub, hash32, r, s), nil
}
