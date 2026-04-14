package ucanauth

import (
	"testing"
	"time"

	"github.com/lerdal/relay-demo/internal/identity"
)

func makeIssuerAndClient(t *testing.T, glob string, ttl time.Duration) (*Issuer, *Verifier, *identity.Identity, *identity.Identity) {
	t.Helper()
	relay, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	client, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return NewIssuer(relay, glob, ttl), NewVerifier(relay), relay, client
}

func TestIssueAndVerifyHappyPath(t *testing.T) {
	iss, ver, _, client := makeIssuerAndClient(t, "demo.*", time.Hour)
	d, err := iss.Issue(client.DIDKey)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ver.VerifyPair(client.DIDKey, d.Publish, d.Subscribe)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if v.Publish.Command().String() != "/nats/publish" {
		t.Fatalf("unexpected publish command: %s", v.Publish.Command())
	}
	if v.Subscribe.Command().String() != "/nats/subscribe" {
		t.Fatalf("unexpected subscribe command: %s", v.Subscribe.Command())
	}
}

func TestVerifyRejectsWrongAudience(t *testing.T) {
	iss, ver, _, client := makeIssuerAndClient(t, "demo.*", time.Hour)
	d, err := iss.Issue(client.DIDKey)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := identity.Generate()
	if _, err := ver.VerifyPair(other.DIDKey, d.Publish, d.Subscribe); err == nil {
		t.Fatal("expected audience mismatch error")
	}
}

func TestVerifyRejectsTamperedBytes(t *testing.T) {
	iss, ver, _, client := makeIssuerAndClient(t, "demo.*", time.Hour)
	d, err := iss.Issue(client.DIDKey)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte somewhere in the middle of the publish envelope.
	tampered := make([]byte, len(d.Publish))
	copy(tampered, d.Publish)
	tampered[len(tampered)/2] ^= 0x42
	if _, err := ver.VerifyPair(client.DIDKey, tampered, d.Subscribe); err == nil {
		t.Fatal("expected tampered envelope to fail")
	}
}

func TestCheckSubjectAllowAndDeny(t *testing.T) {
	iss, ver, _, client := makeIssuerAndClient(t, "demo.*", time.Hour)
	d, err := iss.Issue(client.DIDKey)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ver.VerifyPair(client.DIDKey, d.Publish, d.Subscribe)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		subject string
		wantErr bool
	}{
		{"demo.foo", false},
		{"demo.foo.bar", false},
		{"demo.", false},
		{"other.bar", true},
		{"", true},
	}
	for _, c := range cases {
		err := CheckSubject(v.Publish, c.subject)
		if (err != nil) != c.wantErr {
			t.Errorf("CheckSubject(%q): gotErr=%v wantErr=%v", c.subject, err, c.wantErr)
		}
	}
}
