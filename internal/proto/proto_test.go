package proto

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type vectors struct {
	Code, Session, AgentID, AgentNonce, ServerNonce, TLSFP string
	CodeIDv, PairSecretv, ServerProofv, ServerProofNoTLS   string
	Key                                                    string
	Frames                                                 []struct {
		Direction string          `json:"direction"`
		Seq       int64           `json:"seq"`
		T         int64           `json:"t"`
		Message   json.RawMessage `json:"message"`
		Frame     string          `json:"frame"`
	}
}

func load(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	var v vectors
	str := func(k string, dst *string) {
		if err := json.Unmarshal(raw[k], dst); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
	}
	str("code", &v.Code)
	str("session", &v.Session)
	str("agent_id", &v.AgentID)
	str("agent_nonce", &v.AgentNonce)
	str("server_nonce", &v.ServerNonce)
	str("tls_fp", &v.TLSFP)
	str("code_id", &v.CodeIDv)
	str("pair_secret", &v.PairSecretv)
	str("server_proof", &v.ServerProofv)
	str("server_proof_no_tls", &v.ServerProofNoTLS)
	str("key", &v.Key)
	if err := json.Unmarshal(raw["frames"], &v.Frames); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPairingVectors(t *testing.T) {
	v := load(t)
	if got := CodeID(v.Code); got != v.CodeIDv {
		t.Errorf("code_id %s, want %s", got, v.CodeIDv)
	}
	s := PairSecret(v.Code)
	if s != v.PairSecretv {
		t.Errorf("pair_secret %s, want %s", s, v.PairSecretv)
	}
	if got := ServerProof(s, v.Session, v.AgentID, v.AgentNonce, v.ServerNonce, v.TLSFP); got != v.ServerProofv {
		t.Errorf("server_proof %s, want %s", got, v.ServerProofv)
	}
	if got := ServerProof(s, v.Session, v.AgentID, v.AgentNonce, v.ServerNonce, ""); got != v.ServerProofNoTLS {
		t.Errorf("server_proof without TLS %s, want %s", got, v.ServerProofNoTLS)
	}
	if got := AgentKey(s, v.AgentID, v.AgentNonce, v.ServerNonce); got != v.Key {
		t.Errorf("key %s, want %s", got, v.Key)
	}
}

func TestFrameVectors(t *testing.T) {
	v := load(t)
	last := map[string]int64{}
	for _, f := range v.Frames {
		made, err := MakeFrame(v.Key, f.Direction, v.Session, v.AgentID, f.Seq, f.T, f.Message)
		if err != nil {
			t.Fatal(err)
		}
		if string(made) != f.Frame {
			t.Errorf("frame\n got %s\nwant %s", made, f.Frame)
		}
		got, err := ReadFrame([]byte(f.Frame), v.Key, f.Direction, v.Session, v.AgentID, last[f.Direction], f.T+5)
		if err != nil {
			t.Fatalf("frame %d: %v", f.Seq, err)
		}
		last[f.Direction] = got.Seq
		var want, have any
		json.Unmarshal(f.Message, &want)
		json.Unmarshal(got.Body, &have)
		wb, _ := json.Marshal(want)
		hb, _ := json.Marshal(have)
		if string(wb) != string(hb) {
			t.Errorf("message %s, want %s", hb, wb)
		}
	}
}

func TestRefused(t *testing.T) {
	v := load(t)
	f := v.Frames[0]
	read := func(text, dir, session, key string, last, now int64) error {
		_, err := ReadFrame([]byte(text), key, dir, session, v.AgentID, last, now)
		return err
	}
	edit := func(k string, val any) string {
		var m map[string]any
		json.Unmarshal([]byte(f.Frame), &m)
		if val == nil {
			m["extra"] = 1
		} else {
			m[k] = val
		}
		b, _ := json.Marshal(m)
		return string(b)
	}
	cases := []struct {
		name, want string
		err        error
	}{
		{"good", "", read(f.Frame, f.Direction, v.Session, v.Key, 0, f.T)},
		{"other session", "bad signature", read(f.Frame, f.Direction, strings.Repeat("ff", 16), v.Key, 0, f.T)},
		{"reflected", "bad signature", read(f.Frame, ToAgent, v.Session, v.Key, 0, f.T)},
		{"other key", "bad signature", read(f.Frame, f.Direction, v.Session, strings.Repeat("0", 64), 0, f.T)},
		{"replay", "replayed", read(f.Frame, f.Direction, v.Session, v.Key, 1, f.T)},
		{"clock", "clock off", read(f.Frame, f.Direction, v.Session, v.Key, 0, f.T+MaxSkew+1)},
		{"clock edge", "", read(f.Frame, f.Direction, v.Session, v.Key, 0, f.T-MaxSkew)},
		{"tampered seq", "bad signature", read(edit("seq", 7), f.Direction, v.Session, v.Key, 0, f.T)},
		{"seq as text", "not a frame", read(edit("seq", "1"), f.Direction, v.Session, v.Key, 0, f.T)},
		{"seq as bool", "not a frame", read(edit("seq", true), f.Direction, v.Session, v.Key, 0, f.T)},
		{"extra key", "not a frame", read(edit("", nil), f.Direction, v.Session, v.Key, 0, f.T)},
		{"bad id", "not a frame", read(edit("id", "../etc"), f.Direction, v.Session, v.Key, 0, f.T)},
		{"not JSON", "not JSON", read("{", f.Direction, v.Session, v.Key, 0, f.T)},
	}
	for _, c := range cases {
		if c.want == "" && c.err != nil {
			t.Errorf("%s: %v", c.name, c.err)
		}
		if c.want != "" && (c.err == nil || !strings.Contains(c.err.Error(), c.want)) {
			t.Errorf("%s: got %v, want %q", c.name, c.err, c.want)
		}
	}
}

type sealVectors struct {
	Seal struct {
		Cmd, Nonce, Text, Box string
		Short                 struct{ Text, Box string }
	}
	Registries [][2]string
}

func loadSeal(t *testing.T) sealVectors {
	t.Helper()
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v sealVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSealVectors(t *testing.T) {
	v, s := load(t), loadSeal(t).Seal
	box, err := Seal(v.Key, v.Session, s.Cmd, s.Nonce, s.Text)
	if err != nil || box != s.Box {
		t.Fatalf("seal %s %v, want %s", box, err, s.Box)
	}
	if text, err := Unseal(v.Key, v.Session, s.Cmd, s.Nonce, s.Box); err != nil || text != s.Text {
		t.Fatalf("unseal %q %v", text, err)
	}
	if box, _ := Seal(v.Key, v.Session, s.Cmd, s.Nonce, s.Short.Text); box != s.Short.Box {
		t.Errorf("short seal %s, want %s", box, s.Short.Box)
	}
	for _, other := range [][4]string{{v.Key, strings.Repeat("ff", 16), s.Cmd, s.Nonce}, {v.Key, v.Session, strings.Repeat("f", 16), s.Nonce},
		{v.Key, v.Session, s.Cmd, strings.Repeat("00", 16)}, {strings.Repeat("0", 64), v.Session, s.Cmd, s.Nonce}} {
		if text, _ := Unseal(other[0], other[1], other[2], other[3], s.Box); text == s.Text {
			t.Errorf("opened with %v", other)
		}
	}
	for _, bad := range []string{"abc", "ZZ", "AB"} {
		if _, err := Unseal(v.Key, v.Session, s.Cmd, s.Nonce, bad); err == nil {
			t.Errorf("unsealed %q", bad)
		}
	}
	if _, err := Seal(v.Key, v.Session, s.Cmd, "xyz", "t"); err == nil {
		t.Error("sealed with a bad nonce")
	}
	if _, err := Seal(v.Key, v.Session, s.Cmd, s.Nonce, strings.Repeat("x", MaxSealed+1)); err == nil {
		t.Error("sealed too much")
	}
}

// The command frame of the vectors carries the login sealed, and the agent opens it.
func TestSealedCommandFrame(t *testing.T) {
	v, s := load(t), loadSeal(t).Seal
	for _, f := range v.Frames {
		var cmd Command
		if json.Unmarshal(f.Message, &cmd) != nil || cmd.Auth == nil {
			continue
		}
		if strings.Contains(f.Frame, "ghp_") {
			t.Fatal("the token is in the frame")
		}
		if !cmd.HoldCritical || cmd.Auth.Registry != "ghcr.io" {
			t.Errorf("command %+v", cmd)
		}
		text, err := Unseal(v.Key, v.Session, cmd.Cmd, cmd.Auth.Nonce, cmd.Auth.Box)
		if err != nil || text != s.Text {
			t.Fatalf("unseal %q %v", text, err)
		}
		return
	}
	t.Fatal("no command with auth in the vectors")
}

func TestRegistryVectors(t *testing.T) {
	for _, r := range loadSeal(t).Registries {
		if got := RegistryOf(r[0]); got != r[1] {
			t.Errorf("RegistryOf(%q) = %q, want %q", r[0], got, r[1])
		}
	}
}
