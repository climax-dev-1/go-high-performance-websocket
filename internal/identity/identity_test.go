package identity

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestDIDKeyRoundTrip(t *testing.T) {
	for i := 0; i < 20; i++ {
		id, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(id.DIDKey, "did:key:z") {
			t.Fatalf("unexpected prefix: %s", id.DIDKey)
		}
		got, err := DecodeDIDKey(id.DIDKey)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, id.StdPub) {
			t.Fatalf("round-trip mismatch: %x vs %x", got, id.StdPub)
		}
	}
}

func TestDIDKeyKnownSeed(t *testing.T) {
	seed := bytes.Repeat([]byte{0x00}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	did := EncodeDIDKey(pub)

	pub2, err := DecodeDIDKey(did)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub2, pub) {
		t.Fatalf("decoded key mismatch")
	}
}

func TestDecodeDIDKeyRejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"did:web:example.com",
		"did:key:zNotBase58",
		"did:key:abc",
	}
	for _, c := range cases {
		if _, err := DecodeDIDKey(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestVerifyChallenge(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("the quick brown fox jumps over the lazy dog!!!!!")[:32]
	sig := ed25519.Sign(id.StdPriv, nonce)
	if err := VerifyChallenge(id.DIDKey, nonce, sig); err != nil {
		t.Fatalf("expected valid sig: %v", err)
	}
	// Tamper the signature.
	sig[0] ^= 0x01
	if err := VerifyChallenge(id.DIDKey, nonce, sig); err == nil {
		t.Fatal("expected sig to be rejected after tampering")
	}
}
