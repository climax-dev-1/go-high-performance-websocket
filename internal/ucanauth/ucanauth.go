// Package ucanauth bridges go-ucan delegation tokens with the relay's wire
// protocol. It issues, verifies, and evaluates capability checks against
// incoming publish/subscribe requests.
//
// The demo uses root delegations (iss == sub) with the relay acting as the
// issuer for every client. In production this would be replaced by a proper
// delegation chain rooted at an external identity provider.
package ucanauth

import (
	"errors"
	"fmt"
	"time"

	didit "github.com/MetaMask/go-did-it"
	"github.com/ipld/go-ipld-prime/datamodel"
	"github.com/ipld/go-ipld-prime/fluent/qp"
	"github.com/ipld/go-ipld-prime/node/basicnode"

	"github.com/ucan-wg/go-ucan/pkg/command"
	"github.com/ucan-wg/go-ucan/pkg/policy"
	"github.com/ucan-wg/go-ucan/token/delegation"

	"github.com/lerdal/relay-demo/internal/identity"
)

// Canonical commands issued by this relay.
var (
	CmdPublish   = command.MustParse("/nats/publish")
	CmdSubscribe = command.MustParse("/nats/subscribe")
)

// Issuer mints root delegations granting publish/subscribe capabilities over a
// subject glob prefix (e.g. "demo.*") to a client.
type Issuer struct {
	ident         *identity.Identity
	subjectGlob   string
	ttl           time.Duration
}

// NewIssuer constructs an Issuer. subjectGlob is the wildcard pattern used in
// the policy's Like statement, e.g. "demo.*".
func NewIssuer(ident *identity.Identity, subjectGlob string, ttl time.Duration) *Issuer {
	return &Issuer{ident: ident, subjectGlob: subjectGlob, ttl: ttl}
}

// Delegations holds the two DAG-CBOR sealed delegation blobs for a client.
type Delegations struct {
	Publish   []byte
	Subscribe []byte
}

// Issue creates a publish delegation and a subscribe delegation for the given
// client DID string, signed by the issuer's Ed25519 key. Both are returned as
// raw DAG-CBOR bytes (wire transport should base64-encode them).
func (i *Issuer) Issue(clientDID string) (*Delegations, error) {
	aud, err := didit.Parse(clientDID)
	if err != nil {
		return nil, fmt.Errorf("issuer: parse client did: %w", err)
	}
	pubBytes, err := i.issueOne(aud, CmdPublish)
	if err != nil {
		return nil, fmt.Errorf("issuer: publish delegation: %w", err)
	}
	subBytes, err := i.issueOne(aud, CmdSubscribe)
	if err != nil {
		return nil, fmt.Errorf("issuer: subscribe delegation: %w", err)
	}
	return &Delegations{Publish: pubBytes, Subscribe: subBytes}, nil
}

func (i *Issuer) issueOne(aud didit.DID, cmd command.Command) ([]byte, error) {
	pol := policy.MustConstruct(
		policy.Like(".subject", i.subjectGlob),
	)
	tkn, err := delegation.Root(i.ident.DID, aud, cmd, pol,
		delegation.WithExpirationIn(i.ttl),
	)
	if err != nil {
		return nil, err
	}
	data, _, err := tkn.ToSealed(i.ident.SignerKey)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Verified holds a decoded, validated pair of delegation tokens bound to a client.
type Verified struct {
	Publish   *delegation.Token
	Subscribe *delegation.Token
}

// Verifier decodes and validates sealed delegations against relay expectations.
type Verifier struct {
	relayDID didit.DID
}

func NewVerifier(ident *identity.Identity) *Verifier {
	return &Verifier{relayDID: ident.DID}
}

// VerifyPair decodes the two sealed delegation envelopes and checks:
//   - envelope signature is valid (handled by delegation.FromSealed)
//   - issuer is the relay itself (root delegation issued by us)
//   - audience equals the given client DID string
//   - token is not expired
//   - commands are exactly /nats/publish and /nats/subscribe
func (v *Verifier) VerifyPair(clientDID string, pubSealed, subSealed []byte) (*Verified, error) {
	aud, err := didit.Parse(clientDID)
	if err != nil {
		return nil, fmt.Errorf("verifier: parse client did: %w", err)
	}
	pubTok, err := v.verifyOne(pubSealed, aud, CmdPublish)
	if err != nil {
		return nil, fmt.Errorf("publish token: %w", err)
	}
	subTok, err := v.verifyOne(subSealed, aud, CmdSubscribe)
	if err != nil {
		return nil, fmt.Errorf("subscribe token: %w", err)
	}
	return &Verified{Publish: pubTok, Subscribe: subTok}, nil
}

func (v *Verifier) verifyOne(sealed []byte, aud didit.DID, expectedCmd command.Command) (*delegation.Token, error) {
	tkn, _, err := delegation.FromSealed(sealed)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if !tkn.Issuer().Equal(v.relayDID) {
		return nil, errors.New("issuer is not the relay")
	}
	if !tkn.Audience().Equal(aud) {
		return nil, errors.New("audience does not match client")
	}
	if !tkn.IsValidNow() {
		return nil, errors.New("token is expired or not yet valid")
	}
	if tkn.Command().String() != expectedCmd.String() {
		return nil, fmt.Errorf("unexpected command %q", tkn.Command())
	}
	return tkn, nil
}

// CheckSubject builds a tiny IPLD map { "subject": <subject> } and evaluates it
// against the token's policy. This is how we enforce the subject glob on
// every publish/subscribe request after handshake.
func CheckSubject(tok *delegation.Token, subject string) error {
	node, err := qp.BuildMap(basicnode.Prototype.Map, 1, func(ma datamodel.MapAssembler) {
		qp.MapEntry(ma, "subject", qp.String(subject))
	})
	if err != nil {
		return fmt.Errorf("build policy node: %w", err)
	}
	ok, failed := tok.Policy().Match(node)
	if !ok {
		if failed != nil {
			return fmt.Errorf("policy denied: %s", failed.Kind())
		}
		return errors.New("policy denied")
	}
	return nil
}
