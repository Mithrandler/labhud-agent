package conn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/caps"
	"github.com/Mithrandler/labhud-agent/internal/config"
	"github.com/Mithrandler/labhud-agent/internal/proto"
	"github.com/Mithrandler/labhud-agent/internal/selfupdate"
	"github.com/coder/websocket"
)

const code = "Zm9vYmFyYmF6cXV4MTIzNDU2"

// fakeLabhud plays labhud's side: welcome, the pairing, hello -> allow, then script(s).
type fakeLabhud struct {
	t        *testing.T
	tlsFP    string // what the challenge vouches for
	badProof bool
	allow    proto.Allow
	script   func(s *srvSession)
	keys     sync.Map // id -> key, kept across connections
}

type srvSession struct {
	t       *testing.T
	c       *websocket.Conn
	id, key string
	sid     string
	seqOut  int64
	seqIn   int64
}

func (s *srvSession) send(msg any) {
	s.seqOut++
	b, _ := proto.MakeFrame(s.key, proto.ToAgent, s.sid, s.id, s.seqOut, time.Now().Unix(), msg)
	s.c.Write(context.Background(), websocket.MessageText, b)
}

func (s *srvSession) read() (proto.Frame, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		_, b, err := s.c.Read(ctx)
		if err != nil {
			return proto.Frame{}, err
		}
		f, err := proto.ReadFrame(b, s.key, proto.ToLabhud, s.sid, s.id, s.seqIn, time.Now().Unix())
		if err != nil {
			return f, err
		}
		s.seqIn = f.Seq
		if f.Type != "state" { // states come by themselves; the tests look at the rest
			return f, nil
		}
	}
}

func (f *fakeLabhud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	c.SetReadLimit(1 << 20) // labhud's own limit (websock.MAX_MESSAGE)
	defer c.CloseNow()
	ctx := context.Background()
	sid := strings.Repeat("ab", 16)
	b, _ := json.Marshal(proto.Welcome{Type: "welcome", V: 1, Session: sid})
	c.Write(ctx, websocket.MessageText, b)
	_, first, err := c.Read(ctx)
	if err != nil {
		return
	}
	s := &srvSession{t: f.t, c: c, sid: sid}
	var p proto.Pair
	json.Unmarshal(first, &p)
	if p.Type == "pair" {
		if p.CodeID != proto.CodeID(code) {
			c.Write(ctx, websocket.MessageText, []byte(`{"type":"error","error":"the code is wrong or expired"}`))
			return
		}
		secret := proto.PairSecret(code)
		sn := strings.Repeat("cd", 16)
		s.id = "a1b2c3d4"
		proof := proto.ServerProof(secret, sid, s.id, p.AgentNonce, sn, f.tlsFP)
		if f.badProof {
			proof = strings.Repeat("0", 64)
		}
		b, _ := json.Marshal(proto.Challenge{Type: "challenge", AgentID: s.id, ServerNonce: sn, TLSFP: f.tlsFP, Proof: proof})
		c.Write(ctx, websocket.MessageText, b)
		s.key = proto.AgentKey(secret, s.id, p.AgentNonce, sn)
		f.keys.Store(s.id, s.key)
		_, first, err = c.Read(ctx)
		if err != nil {
			return
		}
	} else {
		s.id = "a1b2c3d4"
		k, _ := f.keys.Load(s.id)
		s.key, _ = k.(string)
	}
	fr, err := proto.ReadFrame(first, s.key, proto.ToLabhud, sid, s.id, 0, time.Now().Unix())
	if err != nil || fr.Type != "hello" {
		c.Write(ctx, websocket.MessageText, []byte(`{"type":"error","error":"bad signature"}`))
		return
	}
	s.seqIn = fr.Seq
	s.send(proto.Allow{Type: "allow", Caps: f.allow.Caps, Targets: f.allow.Targets})
	if f.script != nil {
		f.script(s)
	}
}

// fakeCap records what it was asked to do.
type fakeCap struct {
	mu   sync.Mutex
	done []string
}

func (c *fakeCap) Name() string { return "docker" }
func (c *fakeCap) Fill(_ context.Context, st *proto.State) {
	st.Containers = map[string]map[string]any{"jellyfin": {"state": "running"}}
}
func (c *fakeCap) Do(_ context.Context, verb, target string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.done = append(c.done, verb+" "+target)
	if target == "broken" {
		return errors.New("no such container")
	}
	return nil
}

func (c *fakeCap) Reads(verb string) bool { return verb == "logs" }
func (c *fakeCap) Read(_ context.Context, verb, target string) (string, error) {
	return strings.Repeat("x", caps.MaxOutput) + "last line of " + target + "\n", nil
}

func newAgent(t *testing.T, url string, c caps.Cap) *Agent {
	return &Agent{Cfg: config.Config{Dir: t.TempDir(), URL: url, Code: code, Root: "/"},
		Version: "test", Caps: []caps.Cap{c}, Log: log.New(io.Discard, "", 0),
		SampleEvery: 50 * time.Millisecond, PingEvery: time.Second}
}

func TestPairCommandAndBye(t *testing.T) {
	cap := &fakeCap{}
	results := make(chan proto.Result, 6)
	f := &fakeLabhud{t: t, allow: proto.Allow{Caps: []string{"docker"},
		Targets: map[string][]string{"docker": {"jellyfin", "broken"}}}}
	f.script = func(s *srvSession) {
		for i, cmd := range []proto.Command{
			{Cap: "docker", Verb: "restart", Target: "jellyfin"},
			{Cap: "docker", Verb: "restart", Target: "plex"}, // not ticked: refused by the agent
			{Cap: "docker", Verb: "exec", Target: "jellyfin"},
			{Cap: "docker", Verb: "stop", Target: "broken"},
			{Cap: "docker", Verb: "logs", Target: "jellyfin"},
			{Cap: "docker", Verb: "logs", Target: "plex"},
		} {
			cmd.Type, cmd.Cmd = "command", strings.Repeat(string(rune('0'+i)), 16)
			s.send(cmd)
			fr, err := s.read()
			if err != nil {
				t.Errorf("reading a result: %v", err)
				return
			}
			var r proto.Result
			json.Unmarshal(fr.Body, &r)
			results <- r
		}
		s.send(proto.Bye{Type: "bye", Reason: "removed"})
		time.Sleep(200 * time.Millisecond)
	}
	srv := httptest.NewServer(f)
	defer srv.Close()
	a := newAgent(t, srv.URL, cap)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.Run(ctx); !errors.Is(err, ErrRemoved) {
		t.Fatalf("Run: %v, want ErrRemoved", err)
	}
	want := []struct {
		ok  bool
		err string
	}{{true, ""}, {false, "not allowed"}, {false, "not allowed"}, {false, "no such container"}, {true, ""}, {false, "not allowed"}}
	for i, w := range want {
		r := <-results
		if r.OK != w.ok || r.Error != w.err {
			t.Errorf("command %d: %+v, want %+v", i, r.Error, w)
		}
		if i == 4 && (len(r.Output) != caps.MaxOutput || !strings.HasSuffix(r.Output, "last line of jellyfin\n")) {
			t.Errorf("logs: %d bytes, the newest kept: %q", len(r.Output), r.Output[len(r.Output)-30:])
		}
	}
	if strings.Join(cap.done, ",") != "restart jellyfin,stop broken" {
		t.Errorf("the capability did %v", cap.done)
	}
	if _, err := os.Stat(filepath.Join(a.Cfg.Dir, "key")); !os.IsNotExist(err) {
		t.Error("the key was not deleted after bye")
	}
}

func TestReconnectWithKey(t *testing.T) {
	f := &fakeLabhud{t: t}
	connected := make(chan struct{}, 2)
	f.script = func(s *srvSession) { connected <- struct{}{} }
	srv := httptest.NewServer(f)
	defer srv.Close()
	a := newAgent(t, srv.URL, &fakeCap{})
	a.defaults()
	ctx := context.Background()
	a.Once(ctx) // pairs; the fake ends the connection after the script
	a.Cfg.Code = ""
	if err := a.Once(ctx); err != nil && errors.Is(err, ErrPairing) {
		t.Fatalf("second connection: %v", err)
	}
	if len(connected) != 2 {
		t.Errorf("%d connections, want 2", len(connected))
	}
}

func TestWrongProof(t *testing.T) {
	srv := httptest.NewServer(&fakeLabhud{t: t, badProof: true})
	defer srv.Close()
	a := newAgent(t, srv.URL, &fakeCap{})
	err := a.Run(context.Background())
	if !errors.Is(err, ErrPairing) || !strings.Contains(err.Error(), "wrong proof") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(a.Cfg.Dir, "key")); !os.IsNotExist(err) {
		t.Error("a key was kept after a wrong proof")
	}
}

func TestWrongCode(t *testing.T) {
	srv := httptest.NewServer(&fakeLabhud{t: t})
	defer srv.Close()
	a := newAgent(t, srv.URL, &fakeCap{})
	a.Cfg.Code = "guessed"
	if err := a.Run(context.Background()); !errors.Is(err, ErrPairing) || !strings.Contains(err.Error(), "wrong or expired") {
		t.Fatalf("got %v", err)
	}
}

func certFP(srv *httptest.Server) string {
	sum := sha256.Sum256(srv.Certificate().Raw)
	return hex.EncodeToString(sum[:])
}

func TestTLSPinned(t *testing.T) {
	f := &fakeLabhud{t: t}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	f.tlsFP = certFP(srv)
	a := newAgent(t, srv.URL, &fakeCap{})
	a.defaults()
	a.Once(context.Background())
	id, _ := config.LoadIdentity(a.Cfg.Dir)
	if id == nil || id.TLSFP != f.tlsFP {
		t.Fatalf("pin not kept: %+v", id)
	}
	// the same labhud with another certificate: refused
	id.TLSFP = strings.Repeat("0", 64)
	id.Save(a.Cfg.Dir)
	a.Cfg.Code = ""
	if err := a.Once(context.Background()); err == nil || !strings.Contains(err.Error(), "certificate changed") {
		t.Fatalf("got %v", err)
	}
}

func TestTLSProofForAnotherCertificate(t *testing.T) {
	f := &fakeLabhud{t: t, tlsFP: strings.Repeat("1", 64)} // a man in the middle shows his own
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	a := newAgent(t, srv.URL, &fakeCap{})
	if err := a.Run(context.Background()); !errors.Is(err, ErrPairing) || !strings.Contains(err.Error(), "another certificate") {
		t.Fatalf("got %v", err)
	}
}

func TestOtherLabhud(t *testing.T) {
	a := newAgent(t, "http://192.0.2.1:8095", &fakeCap{})
	(&config.Identity{ID: "a1b2c3d4", Key: "k", URL: "http://192.0.2.9:8095"}).Save(a.Cfg.Dir)
	if err := a.Run(context.Background()); !errors.Is(err, ErrPairing) {
		t.Fatalf("got %v", err)
	}
}

func TestUpdate(t *testing.T) {
	bin := []byte("labhud-agent 0.1.0")
	sum := sha256.Sum256(bin)
	want := hex.EncodeToString(sum[:])
	rel := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v0.1.0/SHA256SUMS":
			w.Write([]byte(want + "  " + selfupdate.Asset() + "\n"))
		case "/v0.1.0/" + selfupdate.Asset():
			w.Write(bin)
		default:
			http.NotFound(w, r)
		}
	}))
	defer rel.Close()
	exe := filepath.Join(t.TempDir(), "labhud-agent")
	os.WriteFile(exe, []byte("old"), 0o755)

	results := make(chan proto.Result, 2)
	f := &fakeLabhud{t: t}
	f.script = func(s *srvSession) {
		for i, up := range []proto.Update{
			{Version: "0.1.0", SHA256: strings.Repeat("1", 64)}, // not the release's: refused, the agent goes on
			{Version: "0.1.0", SHA256: want},
		} {
			up.Type, up.Cmd = "update", strings.Repeat(string(rune('a'+i)), 16)
			s.send(up)
			fr, err := s.read()
			if err != nil {
				t.Errorf("reading a result: %v", err)
				return
			}
			var r proto.Result
			json.Unmarshal(fr.Body, &r)
			results <- r
		}
		time.Sleep(time.Second)
	}
	srv := httptest.NewServer(f)
	defer srv.Close()
	a := newAgent(t, srv.URL, &fakeCap{})
	a.Update = &selfupdate.Updater{Own: "0.0.1", Releases: rel.URL, Exe: exe, Client: rel.Client()}
	started := make(chan string, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a.Exec = func(p string) error { started <- p; cancel(); return nil }
	go a.Run(ctx)
	if r := <-results; r.OK || !strings.Contains(r.Error, "not the release's") {
		t.Errorf("first update: %+v", r)
	}
	if r := <-results; !r.OK {
		t.Errorf("second update: %+v", r)
	}
	select {
	case p := <-started:
		if p != exe {
			t.Errorf("exec %s", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the new binary was not started")
	}
	if b, _ := os.ReadFile(exe); string(b) != string(bin) {
		t.Errorf("binary is %q", b)
	}
}

// stackCap is a stacks capability that records the files it was given.
type stackCap struct {
	files map[string]string
	verb  string
}

func (c *stackCap) Name() string                                        { return "stacks" }
func (c *stackCap) Fill(context.Context, *proto.State)                  {}
func (c *stackCap) Do(context.Context, string, string) error            { return nil }
func (c *stackCap) Reads(verb string) bool                              { return true }
func (c *stackCap) Timeout(string) time.Duration                        { return time.Minute }
func (c *stackCap) Read(_ context.Context, v, t string) (string, error) { return "read " + v, nil }
func (c *stackCap) Deploy(_ context.Context, verb, target string, files map[string]string) (string, error) {
	c.files, c.verb = files, verb
	return "deployed " + target, nil
}

func TestSealedStackFiles(t *testing.T) {
	cap := &stackCap{}
	results := make(chan proto.Result, 3)
	f := &fakeLabhud{t: t, allow: proto.Allow{Caps: []string{"stacks"}, Targets: map[string][]string{"stacks": {"web"}}}}
	f.script = func(s *srvSession) {
		nonce := strings.Repeat("ab", 16)
		seal := func(cmd, text string) *proto.SealedFiles {
			box, err := proto.SealMax(s.key, s.sid, cmd, nonce, text, proto.MaxSealedFiles)
			if err != nil {
				t.Error(err)
			}
			return &proto.SealedFiles{Nonce: nonce, Box: box}
		}
		for i, cmd := range []proto.Command{
			{Cap: "stacks", Verb: "deploy", Target: "web", Files: seal("0000000000000000", `{"compose":"services: {}","env":"A=1"}`)},
			// sealed for another command: it does not open
			{Cap: "stacks", Verb: "deploy", Target: "web", Files: seal("9999999999999999", `{"compose":"x"}`)},
			{Cap: "stacks", Verb: "down", Target: "web"},
		} {
			cmd.Type, cmd.Cmd = "command", strings.Repeat(string(rune('0'+i)), 16)
			s.send(cmd)
			fr, err := s.read()
			if err != nil {
				t.Errorf("reading a result: %v", err)
				return
			}
			var r proto.Result
			json.Unmarshal(fr.Body, &r)
			results <- r
		}
		s.send(proto.Bye{Type: "bye", Reason: "removed"})
		time.Sleep(200 * time.Millisecond)
	}
	srv := httptest.NewServer(f)
	defer srv.Close()
	a := newAgent(t, srv.URL, cap)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.Run(ctx); !errors.Is(err, ErrRemoved) {
		t.Fatalf("Run: %v", err)
	}
	r := <-results
	if !r.OK || r.Output != "deployed web" || cap.files["compose"] != "services: {}" || cap.files["env"] != "A=1" {
		t.Errorf("deploy: %+v, files %v", r, cap.files)
	}
	if r := <-results; r.OK || r.Error != "the files do not open" {
		t.Errorf("a box sealed for another command: %+v", r)
	}
	if r := <-results; !r.OK || r.Output != "read down" {
		t.Errorf("down: %+v", r)
	}
}
