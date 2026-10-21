// Package proto is the agent protocol's cryptography and messages: pairing from the one-time
// code and signed frames. It mirrors labhud's agentproto.py; both are checked against the same
// vectors (testdata/vectors.json, a copy of labhud's docs/agent-protocol-vectors.json).
// The protocol is described in labhud's docs/agent-protocol.md.
package proto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

const (
	V        = "labhud-agent/v1"
	MaxSkew  = 30 // seconds a frame's time may differ from ours
	ToLabhud = "a2l"
	ToAgent  = "l2a"
)

var (
	hex16   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex32   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	agentID = regexp.MustCompile(`^[0-9a-f]{8}$`)
)

// mac is HMAC-SHA256 in lowercase hex. A key that is itself hex is used as its ASCII text.
func mac(key, msg string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(msg))
	return hex.EncodeToString(h.Sum(nil))
}

// CodeID is what the agent sends instead of the code.
func CodeID(code string) string {
	s := sha256.Sum256([]byte(V + "|code-id|" + code))
	return hex.EncodeToString(s[:])
}

// PairSecret is what both sides derive from the code.
func PairSecret(code string) string { return mac(code, V+"|pair-secret") }

// ServerProof is labhud's answer to a pairing; tlsFP is empty over plain ws://.
func ServerProof(secret, session, id, agentNonce, serverNonce, tlsFP string) string {
	return mac(secret, V+"|server-proof|"+session+"|"+id+"|"+agentNonce+"|"+serverNonce+"|"+tlsFP)
}

// AgentKey is the agent's own key, the same on both sides, never sent.
func AgentKey(secret, id, agentNonce, serverNonce string) string {
	return mac(secret, V+"|key|"+id+"|"+agentNonce+"|"+serverNonce)
}

// FrameSig signs one frame.
func FrameSig(key, dir, session, id string, seq, t int64, body string) string {
	return mac(key, V+"|frame|"+dir+"|"+session+"|"+id+"|"+strconv.FormatInt(seq, 10)+"|"+
		strconv.FormatInt(t, 10)+"|"+body)
}

// ProofOK compares a proof in constant time.
func ProofOK(got, want string) bool { return hmac.Equal([]byte(got), []byte(want)) }

// ValidNonce says whether s is 16 bytes of hex, as nonces and sessions are.
func ValidNonce(s string) bool { return hex16.MatchString(s) }

// ValidID says whether s is an agent id.
func ValidID(s string) bool { return agentID.MatchString(s) }

type frame struct {
	ID   string `json:"id"`
	Seq  int64  `json:"seq"`
	T    int64  `json:"t"`
	Body string `json:"body"`
	Sig  string `json:"sig"`
}

// MakeFrame signs a message (anything that marshals to a JSON object with a "type").
func MakeFrame(key, dir, session, id string, seq, t int64, message any) ([]byte, error) {
	body, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	b := string(body)
	return json.Marshal(frame{id, seq, t, b, FrameSig(key, dir, session, id, seq, t, b)})
}

// Frame is a checked frame: its seq and the message's type and raw JSON.
type Frame struct {
	Seq  int64
	Type string
	Body json.RawMessage
}

// ReadFrame checks a frame from labhud (or, in tests, from the agent) and returns it. lastSeq
// is the highest seq seen on this connection in this direction; the new one must be higher.
func ReadFrame(text []byte, key, dir, session, id string, lastSeq, now int64) (Frame, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(text, &raw); err != nil {
		return Frame{}, errors.New("not JSON")
	}
	if len(raw) != 5 {
		return Frame{}, errors.New("not a frame")
	}
	var f frame
	for k, dst := range map[string]any{"id": &f.ID, "seq": &f.Seq, "t": &f.T, "body": &f.Body, "sig": &f.Sig} {
		v, ok := raw[k]
		if !ok || json.Unmarshal(v, dst) != nil {
			return Frame{}, errors.New("not a frame")
		}
	}
	if !agentID.MatchString(f.ID) || !hex32.MatchString(f.Sig) {
		return Frame{}, errors.New("not a frame")
	}
	if f.ID != id || !hmac.Equal([]byte(f.Sig), []byte(FrameSig(key, dir, session, f.ID, f.Seq, f.T, f.Body))) {
		return Frame{}, errors.New("bad signature")
	}
	if f.Seq <= lastSeq {
		return Frame{}, errors.New("replayed frame")
	}
	if d := f.T - now; d > MaxSkew || d < -MaxSkew {
		return Frame{}, fmt.Errorf("clock off by %+d s", d)
	}
	var head struct {
		Type string `json:"type"`
	}
	if json.Unmarshal([]byte(f.Body), &head) != nil || head.Type == "" {
		return Frame{}, errors.New("body without a type")
	}
	return Frame{Seq: f.Seq, Type: head.Type, Body: json.RawMessage(f.Body)}, nil
}
