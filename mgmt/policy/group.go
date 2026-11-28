package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/safing/jess"
)

// TypeGroupPolicy is the value of GroupPolicy.Type.
const TypeGroupPolicy = "group-policy"

var (
	// ErrNotOfflineSigned is returned when a client with a pinned offline
	// key gets a policy without a group policy signed with it.
	ErrNotOfflineSigned = errors.New("policy is not signed with the offline key")
	// ErrOfflineKeyChanged is returned when a policy names another offline
	// key than the pinned one.
	ErrOfflineKeyChanged = errors.New("policy names another offline key than the pinned one")
	// ErrNoOfflineKey is returned for a signed group policy without an
	// offline key to check it.
	ErrNoOfflineKey = errors.New("signed group policy without offline key")
	// ErrWrongGroup is returned when the signed group policy is for another
	// group than the policy around it.
	ErrWrongGroup = errors.New("signed group policy is for another group")
	// ErrGroupRollback is returned for a signed group policy older than the
	// applied one of the same group.
	ErrGroupRollback = errors.New("signed group policy is older than the applied one")
)

// GroupPolicy is the content of the policy of a group. With offline signing
// it is signed on an admin computer with the offline key, and the server
// only passes it on: a server alone cannot change what the computers apply.
type GroupPolicy struct {
	Type  string `json:"type"`
	Group string `json:"group"`
	// Version is set when signing (Unix seconds of the signing time);
	// clients refuse an older version of the same group.
	Version uint64    `json:"version"`
	Signed  time.Time `json:"signed,omitzero"`

	Settings     map[string]any    `json:"settings"`
	Locked       []string          `json:"locked,omitempty"`
	Rules        *Rules            `json:"rules,omitempty"`
	Profiles     []json.RawMessage `json:"profiles,omitempty"`
	BlockSummary bool              `json:"blockSummary,omitempty"`
}

// ParseGroupPolicy parses an unsigned group policy, e.g. one exported for
// signing.
func ParseGroupPolicy(data []byte) (*GroupPolicy, error) {
	gp := &GroupPolicy{}
	err := json.Unmarshal(data, gp)
	if err != nil {
		return nil, fmt.Errorf("parse group policy: %w", err)
	}
	if gp.Type != TypeGroupPolicy {
		return nil, ErrWrongType
	}
	if gp.Group == "" {
		return nil, fmt.Errorf("%w: no group", ErrWrongType)
	}
	return gp, nil
}

// SignGroup sets the version and the signing time and signs the group
// policy with the offline key.
func SignGroup(gp *GroupPolicy, key *jess.Signet, now time.Time) ([]byte, error) {
	gp.Type = TypeGroupPolicy
	gp.Signed = now.UTC().Truncate(time.Second)
	gp.Version = uint64(gp.Signed.Unix()) //nolint:gosec // Signing times are after 1970.
	data, err := json.Marshal(gp)
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}
	return signJSON(data, key)
}

// VerifyGroup checks the signature of a signed group policy against the
// offline key and returns it.
func VerifyGroup(data []byte, offlineKey *jess.Signet) (*GroupPolicy, error) {
	err := verifyJSON(data, offlineKey)
	if err != nil {
		return nil, fmt.Errorf("offline signature: %w", err)
	}
	return ParseGroupPolicy(data)
}

// Pins are the offline key and the group versions a client checks signed
// group policies against.
type Pins struct {
	// OfflineKey is the pinned public offline key in jess text format;
	// empty if none is pinned.
	OfflineKey string `json:"offlineKey,omitempty"`
	// GroupVersions are the highest versions of the signed group policies
	// applied per group.
	GroupVersions map[string]uint64 `json:"groupVersions,omitempty"`
}

// Open returns the content of a verified policy. Without a signed group
// policy, the policy is returned as it is, unless an offline key is pinned.
// With one, its offline signature, group and version are checked against
// the pins (or the offline key of the policy, if none is pinned), and the
// content is taken from it. The returned pins are the updated ones to store
// after the policy is applied.
func Open(p *Policy, pins Pins) (*Policy, Pins, error) {
	if len(p.Signed) == 0 {
		if pins.OfflineKey != "" {
			return nil, pins, ErrNotOfflineSigned
		}
		return p, pins, nil
	}

	keyText := pins.OfflineKey
	switch {
	case keyText == "" && p.OfflineKey == "":
		return nil, pins, ErrNoOfflineKey
	case keyText == "":
		// Trust on first use: the policy is signed with the pinned
		// policy key of the server.
		keyText = p.OfflineKey
	case p.OfflineKey != "" && p.OfflineKey != keyText:
		return nil, pins, ErrOfflineKeyChanged
	}
	key, err := jess.RecipientFromTextFormat(keyText)
	if err != nil {
		return nil, pins, fmt.Errorf("offline key: %w", err)
	}
	gp, err := VerifyGroup(p.Signed, key)
	if err != nil {
		return nil, pins, err
	}
	if gp.Group != p.Group {
		return nil, pins, fmt.Errorf("%w: %q, not %q", ErrWrongGroup, gp.Group, p.Group)
	}
	if applied := pins.GroupVersions[gp.Group]; gp.Version < applied {
		return nil, pins, fmt.Errorf("%w: %d < %d", ErrGroupRollback, gp.Version, applied)
	}

	opened := *p
	opened.Settings = gp.Settings
	opened.Locked = gp.Locked
	opened.Rules = gp.Rules
	opened.Profiles = gp.Profiles
	opened.BlockSummary = gp.BlockSummary

	versions := make(map[string]uint64, len(pins.GroupVersions)+1)
	maps.Copy(versions, pins.GroupVersions)
	versions[gp.Group] = gp.Version
	return &opened, Pins{OfflineKey: keyText, GroupVersions: versions}, nil
}
