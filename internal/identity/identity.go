// Package identity handles Ed25519 keypair generation and did:key encoding/decoding.
//
// did:key format for Ed25519:
//
//	did:key:z<base58btc( 0xed 0x01 || 32-byte-pubkey )>
//
// 0xed is the Ed25519 public key multicodec; 0x01 is the varint continuation
// byte (since 0xed has the high bit set). The "z" prefix identifies base58btc
// multibase.
package identity

import (
	stded "crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/mr-tron/base58"

	didit "github.com/MetaMask/go-did-it"
	dided "github.com/MetaMask/go-did-it/crypto/ed25519"
	_ "github.com/MetaMask/go-did-it/verifiers/did-key" // registers did:key decoder in didit.Parse
)

const didKeyPrefix = "did:key:z"

// multicodec prefix for Ed25519 public key: varint(0xed) == 0xed 0x01
var ed25519MulticodecPrefix = []byte{0xed, 0x01}

// Identity wraps an Ed25519 keypair with its did:key string form and go-did-it
// abstractions. The go-did-it DID type is required by ucan-wg/go-ucan when
// constructing delegations; the go-did-it ed25519 PrivateKey is required when
// sealing the delegation envelope.
type Identity struct {
	StdPub    stded.PublicKey
	StdPriv   stded.PrivateKey
	DIDKey    string
	DID       didit.DID
	SignerKey dided.PrivateKey
}

// Generate creates a fresh Ed25519 keypair and derives its did:key identity.
func Generate() (*Identity, error) {
	pub, priv, err := stded.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 generate: %w", err)
	}
	return fromStd(pub, priv)
}

func fromStd(pub stded.PublicKey, priv stded.PrivateKey) (*Identity, error) {
	if len(pub) != stded.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: %d", len(pub))
	}
	didStr := EncodeDIDKey(pub)
	parsed, err := didit.Parse(didStr)
	if err != nil {
		return nil, fmt.Errorf("identity: parse generated did: %w", err)
	}
	signer, err := dided.PrivateKeyFromSeed(priv.Seed())
	if err != nil {
		return nil, fmt.Errorf("identity: seed signer key: %w", err)
	}
	return &Identity{
		StdPub:    pub,
		StdPriv:   priv,
		DIDKey:    didStr,
		DID:       parsed,
		SignerKey: signer,
	}, nil
}

// EncodeDIDKey returns the did:key string for an Ed25519 public key.
func EncodeDIDKey(pub stded.PublicKey) string {
	if len(pub) != stded.PublicKeySize {
		panic(fmt.Sprintf("identity: wrong ed25519 key size %d", len(pub)))
	}
	buf := make([]byte, 0, len(ed25519MulticodecPrefix)+len(pub))
	buf = append(buf, ed25519MulticodecPrefix...)
	buf = append(buf, pub...)
	return didKeyPrefix + base58.Encode(buf)
}

// DecodeDIDKey parses a did:key string and returns the raw Ed25519 public key.
// Returns an error for any non-Ed25519 did:key or malformed input.
func DecodeDIDKey(s string) (stded.PublicKey, error) {
	if !strings.HasPrefix(s, didKeyPrefix) {
		return nil, errors.New("identity: not a did:key with base58btc encoding")
	}
	raw, err := base58.Decode(s[len(didKeyPrefix):])
	if err != nil {
		return nil, fmt.Errorf("identity: base58 decode: %w", err)
	}
	if len(raw) != len(ed25519MulticodecPrefix)+stded.PublicKeySize {
		return nil, fmt.Errorf("identity: unexpected payload length %d", len(raw))
	}
	if raw[0] != ed25519MulticodecPrefix[0] || raw[1] != ed25519MulticodecPrefix[1] {
		return nil, errors.New("identity: not an Ed25519 multicodec")
	}
	out := make(stded.PublicKey, stded.PublicKeySize)
	copy(out, raw[2:])
	return out, nil
}

// VerifyChallenge checks an Ed25519 signature over a nonce against a did:key.
func VerifyChallenge(clientDID string, nonce, sig []byte) error {
	pub, err := DecodeDIDKey(clientDID)
	if err != nil {
		return err
	}
	if !stded.Verify(pub, nonce, sig) {
		return errors.New("identity: signature verification failed")
	}
	return nil
}
