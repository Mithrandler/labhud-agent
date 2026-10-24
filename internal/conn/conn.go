// Package conn is the agent's side of the connection to labhud: dialling, pairing, the signed
// frames, and the loop that sends the state and carries out commands. See labhud's
// docs/agent-protocol.md.
package conn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/allow"
	"github.com/Mithrandler/labhud-agent/internal/caps"
	"github.com/Mithrandler/labhud-agent/internal/config"
	"github.com/Mithrandler/labhud-agent/internal/proto"
	"github.com/Mithrandler/labhud-agent/internal/selfupdate"
	"github.com/coder/websocket"
)

var (
	// ErrRemoved: labhud removed this agent. Its key is deleted; the process should exit 0.
	ErrRemoved = errors.New("removed in labhud: the key is deleted, pair again to come back")
	// ErrPairing: the code or labhud's proof was refused. Retrying cannot help.
	ErrPairing = errors.New("pairing failed")
)

type Agent struct {
	Cfg     config.Config
	Version string
	Caps    []caps.Cap
	Allow   *allow.List
	Log     *log.Logger
	// Update replaces the binary (nil: updates are refused); Exec starts the new one (syscall.Exec)
	Update *selfupdate.Updater
	Exec   func(path string) error

	StateEvery  time.Duration // a state at least this often (30 s)
	SampleEvery time.Duration // how often the state is read to see if it changed (10 s)
	PingEvery   time.Duration // 25 s
	CommandWait time.Duration // labhud waits 45 s; an action gets a little less

	now      func() time.Time
	targetMu sync.Map // target -> *sync.Mutex: one action at a time on the same thing
	updating atomic.Bool
	once     sync.Once
	events   chan proto.Event
}

func (a *Agent) defaults() {
	a.once.Do(func() { a.events = make(chan proto.Event, 16) })
	if a.StateEvery == 0 {
		a.StateEvery = 30 * time.Second
	}
	if a.SampleEvery == 0 {
		a.SampleEvery = 10 * time.Second
	}
	if a.PingEvery == 0 {
		a.PingEvery = 25 * time.Second
	}
	if a.CommandWait == 0 {
		a.CommandWait = 40 * time.Second
	}
	if a.now == nil {
		a.now = time.Now
	}
	if a.Allow == nil {
		a.Allow = &allow.List{}
	}
	if a.Log == nil {
		a.Log = log.New(os.Stderr, "", log.LstdFlags)
	}
}

// Run keeps the agent connected until ctx ends, the agent is removed (ErrRemoved) or pairing
// fails (ErrPairing). Between tries it waits 1 s, 2 s, 4 s … up to 60 s; a connection that
// lasted a minute starts the count again.
func (a *Agent) Run(ctx context.Context) error {
	a.defaults()
	wait := time.Second
	for {
		started := time.Now()
		err := a.Once(ctx)
		if errors.Is(err, ErrRemoved) || errors.Is(err, ErrPairing) || ctx.Err() != nil {
			return err
		}
		if time.Since(started) > time.Minute {
			wait = time.Second
		}
		a.Log.Printf("disconnected: %v; again in %s", err, wait)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		wait = min(wait*2, time.Minute)
	}
}

func wsURL(u string) (string, error) {
	switch {
	case strings.HasPrefix(u, "http://"):
		return "ws://" + strings.TrimPrefix(u, "http://") + "/api/agent/ws", nil
	case strings.HasPrefix(u, "https://"):
		return "wss://" + strings.TrimPrefix(u, "https://") + "/api/agent/ws", nil
	}
	return "", fmt.Errorf("LABHUD_URL must start with http:// or https:// (now %q)", u)
}

// tlsSeen is what the TLS handshake showed: the certificate's SHA-256, and whether the system
// roots trust it (for a labhud behind a proxy with a real certificate, which then has no pin).
type tlsSeen struct {
	fp      string
	trusted bool
}

func nonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// session is one connection after the handshake.
type session struct {
	c       *websocket.Conn
	id, key string
	sid     string
	mu      sync.Mutex
	seqOut  int64
	seqIn   int64
	now     func() time.Time
	streams streamTable // streams.go: what is open on this connection
}

func (s *session) send(ctx context.Context, msg any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seqOut++
	b, err := proto.MakeFrame(s.key, proto.ToLabhud, s.sid, s.id, s.seqOut, s.now().Unix(), msg)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return s.c.Write(wctx, websocket.MessageText, b)
}

// read gives the next signed frame. An unsigned {"type":"error"} from labhud becomes the error.
func (s *session) read(ctx context.Context) (proto.Frame, error) {
	_, b, err := s.c.Read(ctx)
	if err != nil {
		return proto.Frame{}, err
	}
	f, err := proto.ReadFrame(b, s.key, proto.ToAgent, s.sid, s.id, s.seqIn, s.now().Unix())
	if err != nil {
		var u proto.Unsigned
		if json.Unmarshal(b, &u) == nil && u.Type == "error" {
			return proto.Frame{}, fmt.Errorf("labhud refused: %s", u.Error)
		}
		return proto.Frame{}, fmt.Errorf("bad frame from labhud: %w", err)
	}
	s.seqIn = f.Seq
	return f, nil
}

func readJSON(ctx context.Context, c *websocket.Conn, v any) error {
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, b, err := c.Read(rctx)
	if err != nil {
		return err
	}
	var u proto.Unsigned
	if json.Unmarshal(b, &u) == nil && u.Type == "error" {
		return fmt.Errorf("labhud refused: %s", u.Error)
	}
	return json.Unmarshal(b, v)
}

// Once is one connection, from dialling to its end.
func (a *Agent) Once(ctx context.Context) error {
	a.defaults()
	id, err := config.LoadIdentity(a.Cfg.Dir)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPairing, err)
	}
	if id != nil && id.URL != "" && id.URL != a.Cfg.URL {
		return fmt.Errorf("%w: paired with %s, not %s; delete %s to pair again",
			ErrPairing, id.URL, a.Cfg.URL, filepath.Join(a.Cfg.Dir, "key"))
	}
	if id == nil && a.Cfg.Code == "" {
		return fmt.Errorf("%w: not paired yet: set LABHUD_AGENT_CODE to a code from labhud's ⚙ > Agents", ErrPairing)
	}
	u, err := wsURL(a.Cfg.URL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPairing, err)
	}
	seen := &tlsSeen{}
	opts := &websocket.DialOptions{HTTPClient: a.httpClient(id, seen)}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	c, _, err := websocket.Dial(dctx, u, opts)
	cancel()
	if err != nil {
		return err
	}
	defer c.CloseNow()
	c.SetReadLimit(1 << 20)

	var w proto.Welcome
	if err := readJSON(ctx, c, &w); err != nil {
		return err
	}
	if w.Type != "welcome" || w.V != 1 || !proto.ValidNonce(w.Session) {
		return fmt.Errorf("%w: this labhud does not speak agent protocol v1", ErrPairing)
	}
	if id == nil {
		if id, err = a.pair(ctx, c, w.Session, seen); err != nil {
			return err
		}
	}
	s := &session{c: c, id: id.ID, key: id.Key, sid: w.Session, now: a.now}
	if err := s.send(ctx, a.hello()); err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	f, err := s.read(rctx)
	cancel()
	if err != nil {
		return err
	}
	if err := a.handle(ctx, s, f); err != nil {
		return err
	}
	a.Log.Printf("connected to %s as %s", a.Cfg.URL, id.ID)
	defer s.streams.closeAll() // what is open ends with the connection
	return a.loop(ctx, s)
}

func (a *Agent) httpClient(id *config.Identity, seen *tlsSeen) *http.Client {
	pin := ""
	if id != nil {
		pin = id.TLSFP
	}
	cfg := &tls.Config{
		// Checked below instead: by the pin once paired, by labhud's proof while pairing, by
		// the system roots for a labhud that has no certificate of its own (behind a proxy).
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			seen.fp = hex.EncodeToString(sum[:])
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			_, verr := cs.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: cs.ServerName, Intermediates: inter})
			seen.trusted = verr == nil
			switch {
			case pin != "" && seen.fp != pin:
				return fmt.Errorf("labhud's certificate changed (pinned %s…, got %s…): pair again if this is expected", pin[:12], seen.fp[:12])
			case pin == "" && id != nil && !seen.trusted:
				return fmt.Errorf("labhud's certificate is not trusted: %v", verr)
			}
			return nil
		},
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, Proxy: http.ProxyFromEnvironment}}
}

func (a *Agent) pair(ctx context.Context, c *websocket.Conn, sid string, seen *tlsSeen) (*config.Identity, error) {
	an := nonce()
	b, _ := json.Marshal(proto.Pair{Type: "pair", CodeID: proto.CodeID(a.Cfg.Code), AgentNonce: an, Name: a.name()})
	if err := c.Write(ctx, websocket.MessageText, b); err != nil {
		return nil, err
	}
	var ch proto.Challenge
	if err := readJSON(ctx, c, &ch); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPairing, err)
	}
	secret := proto.PairSecret(a.Cfg.Code)
	if ch.Type != "challenge" || !proto.ValidID(ch.AgentID) || !proto.ValidNonce(ch.ServerNonce) ||
		!proto.ProofOK(ch.Proof, proto.ServerProof(secret, sid, ch.AgentID, an, ch.ServerNonce, ch.TLSFP)) {
		return nil, fmt.Errorf("%w: this is not the labhud that made the code (wrong proof)", ErrPairing)
	}
	tlsOn := strings.HasPrefix(a.Cfg.URL, "https://")
	switch {
	case tlsOn && ch.TLSFP != "" && ch.TLSFP != seen.fp:
		return nil, fmt.Errorf("%w: labhud vouches for another certificate than the one this connection shows (a proxy in between?)", ErrPairing)
	case tlsOn && ch.TLSFP == "" && !seen.trusted:
		return nil, fmt.Errorf("%w: labhud has no certificate of its own and the one shown is not trusted", ErrPairing)
	}
	id := &config.Identity{ID: ch.AgentID, Key: proto.AgentKey(secret, ch.AgentID, an, ch.ServerNonce), URL: a.Cfg.URL}
	if tlsOn {
		id.TLSFP = ch.TLSFP
	}
	if err := id.Save(a.Cfg.Dir); err != nil {
		return nil, fmt.Errorf("%w: cannot keep the key: %v", ErrPairing, err)
	}
	a.Log.Printf("paired with %s as %s", a.Cfg.URL, id.ID)
	return id, nil
}

func (a *Agent) name() string {
	if a.Cfg.Name != "" {
		return a.Cfg.Name
	}
	if b, err := os.ReadFile(filepath.Join(a.Cfg.Root, "etc/hostname")); err == nil {
		if h := strings.TrimSpace(string(b)); h != "" {
			return h
		}
	}
	h, _ := os.Hostname()
	return h
}

func (a *Agent) hello() proto.Hello {
	h := proto.Host{Hostname: a.name(), Arch: runtime.GOARCH, MAC: primaryMAC(a.Cfg.Root)}
	if b, err := os.ReadFile(filepath.Join(a.Cfg.Root, "etc/os-release")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
				h.OS = strings.Trim(v, `"'`)
			}
		}
	}
	var u syscall.Utsname
	if syscall.Uname(&u) == nil {
		var sb strings.Builder
		for _, c := range u.Release {
			if c == 0 {
				break
			}
			sb.WriteByte(byte(c))
		}
		h.Kernel = sb.String()
	}
	names := make([]string, 0, len(a.Caps))
	for _, c := range a.Caps {
		names = append(names, c.Name())
	}
	install := "service"
	if a.Cfg.InContainer() {
		install = "container"
	}
	return proto.Hello{Type: "hello", Version: a.Version, Name: a.Cfg.Name, Host: h, Caps: names, Install: install,
		Features: Features}
}

// Features: what this agent understands beyond v1's first messages (hello.features).
var Features = []string{"registry-auth"}

// options opens what an update command adds (a sealed registry login, hold_critical). The login
// lives only in memory, for this one update; it is never logged.
func options(s *session, cmd proto.Command) (caps.UpdateOptions, error) {
	opt := caps.UpdateOptions{HoldCritical: cmd.HoldCritical}
	if cmd.Auth == nil {
		return opt, nil
	}
	text, err := proto.Unseal(s.key, s.sid, cmd.Cmd, cmd.Auth.Nonce, cmd.Auth.Box)
	var l proto.Login
	if err != nil || json.Unmarshal([]byte(text), &l) != nil || l.Username == "" || l.Password == "" {
		return opt, errors.New("the registry login does not open")
	}
	opt.Registry, opt.Login = cmd.Auth.Registry, &l
	return opt, nil
}

// stackFiles opens a deploy's sealed files: {"compose": "…", "env": "…"}.
func stackFiles(s *session, cmd proto.Command) (map[string]string, error) {
	text, err := proto.UnsealMax(s.key, s.sid, cmd.Cmd, cmd.Files.Nonce, cmd.Files.Box, proto.MaxSealedFiles)
	var files map[string]string
	if err != nil || json.Unmarshal([]byte(text), &files) != nil {
		return nil, errors.New("the files do not open")
	}
	return files, nil
}

// loop runs until the connection ends: frames from labhud, the state, the pings.
func (a *Agent) loop(ctx context.Context, s *session) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	go func() {
		t := time.NewTicker(a.PingEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				pctx, pc := context.WithTimeout(ctx, 15*time.Second)
				err := s.c.Ping(pctx)
				pc()
				if err != nil {
					cancel(fmt.Errorf("labhud does not answer pings: %w", err))
					return
				}
			}
		}
	}()
	go func() {
		var last []byte
		var lastSent time.Time
		t := time.NewTicker(a.SampleEvery)
		defer t.Stop()
		for {
			st := a.state(ctx)
			b, _ := json.Marshal(st)
			if !bytes.Equal(b, last) || time.Since(lastSent) >= a.StateEvery {
				if err := s.send(ctx, st); err != nil {
					cancel(err)
					return
				}
				last, lastSent = b, time.Now()
			}
		wait:
			select {
			case <-ctx.Done():
				return
			case ev := <-a.events:
				if err := s.send(ctx, ev); err != nil {
					select { // kept for the next connection, if there is room
					case a.events <- ev:
					default:
					}
					cancel(err)
					return
				}
				goto wait
			case <-t.C:
			}
		}
	}()
	for {
		f, err := s.read(ctx)
		if err != nil {
			if c := context.Cause(ctx); c != nil && !errors.Is(c, context.Canceled) {
				return c
			}
			return err
		}
		if err := a.handle(ctx, s, f); err != nil {
			return err
		}
	}
}

func (a *Agent) state(ctx context.Context) proto.State {
	st := proto.State{Type: "state"}
	for _, c := range a.Caps {
		fctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		c.Fill(fctx, &st)
		cancel()
	}
	return st
}

func (a *Agent) handle(ctx context.Context, s *session, f proto.Frame) error {
	switch f.Type {
	case "allow":
		var al proto.Allow
		if err := json.Unmarshal(f.Body, &al); err != nil {
			return fmt.Errorf("bad allow: %w", err)
		}
		a.Allow.Set(al)
		a.Log.Printf("allowed: %v %v", al.Caps, al.Targets)
	case "command":
		var cmd proto.Command
		if err := json.Unmarshal(f.Body, &cmd); err != nil {
			return fmt.Errorf("bad command: %w", err)
		}
		go a.run(ctx, s, cmd)
	case "open":
		var o proto.Open
		if err := json.Unmarshal(f.Body, &o); err != nil {
			return fmt.Errorf("bad open: %w", err)
		}
		a.openStream(ctx, s, o)
	case "input", "resize", "close":
		var in proto.StreamIn
		if err := json.Unmarshal(f.Body, &in); err != nil {
			return fmt.Errorf("bad %s: %w", f.Type, err)
		}
		in.Type = f.Type
		s.streams.in(in)
	case "update":
		var up proto.Update
		if err := json.Unmarshal(f.Body, &up); err != nil {
			return fmt.Errorf("bad update: %w", err)
		}
		if !a.updating.CompareAndSwap(false, true) {
			a.Log.Printf("update to %s: one is already running", up.Version)
			return nil
		}
		go func() { // the download takes a while: the frames and pings go on meanwhile
			defer a.updating.Store(false)
			if err := a.update(ctx, s, up); err != nil {
				a.Log.Print(err)
			}
		}()
	case "bye":
		var b proto.Bye
		json.Unmarshal(f.Body, &b)
		if b.Reason == "removed" {
			if err := config.Forget(a.Cfg.Dir); err != nil {
				a.Log.Printf("could not delete the key: %v", err)
			}
			return ErrRemoved
		}
		return fmt.Errorf("labhud said bye: %s", b.Reason)
	default:
		a.Log.Printf("ignored a %q from labhud", f.Type)
	}
	return nil
}

func (a *Agent) run(ctx context.Context, s *session, cmd proto.Command) {
	res := proto.Result{Type: "result", Cmd: cmd.Cmd}
	err := a.Allow.Check(cmd.Cap, cmd.Verb, cmd.Target)
	if err == nil {
		err = allow.CheckArg(cmd.Verb, cmd.Arg)
	}
	var target caps.Cap
	if err == nil {
		for _, c := range a.Caps {
			if c.Name() == cmd.Cap {
				target = c
			}
		}
		if target == nil {
			err = errors.New("this host has no " + cmd.Cap)
		}
	}
	if err == nil {
		m, _ := a.targetMu.LoadOrStore(cmd.Cap+"/"+cmd.Target, &sync.Mutex{})
		mu := m.(*sync.Mutex)
		if !mu.TryLock() {
			err = errors.New("already running")
		} else {
			wait := a.CommandWait
			if sl, ok := target.(caps.Slow); ok && sl.Timeout(cmd.Verb) > 0 {
				wait = sl.Timeout(cmd.Verb)
			}
			cctx, cancel := context.WithTimeout(ctx, wait)
			if dp, ok := target.(caps.Deployer); ok && cmd.Files != nil {
				var out string
				if files, ferr := stackFiles(s, cmd); ferr != nil {
					err = ferr
				} else {
					out, err = dp.Deploy(cctx, cmd.Verb, cmd.Target, files)
				}
				if len(out) > caps.MaxOutput {
					out = out[len(out)-caps.MaxOutput:]
				}
				res.Output = out
			} else if ar, ok := target.(caps.ArgRunner); ok && ar.TakesArg(cmd.Verb) {
				var out string
				out, err = ar.RunArg(cctx, cmd.Verb, cmd.Target, cmd.Arg)
				if len(out) > caps.MaxOutput {
					out = out[len(out)-caps.MaxOutput:]
				}
				res.Output = out
			} else if rd, ok := target.(caps.Reader); ok && rd.Reads(cmd.Verb) {
				var out string
				out, err = rd.Read(cctx, cmd.Verb, cmd.Target)
				if len(out) > caps.MaxOutput {
					out = out[len(out)-caps.MaxOutput:] // the newest lines
				}
				res.Output = out
			} else if up, ok := target.(caps.Updater); ok && cmd.Verb == "update" && (cmd.Auth != nil || cmd.HoldCritical) {
				var opt caps.UpdateOptions
				if opt, err = options(s, cmd); err == nil {
					err = up.UpdateWith(cmd.Target, opt)
				}
			} else {
				err = target.Do(cctx, cmd.Verb, cmd.Target)
			}
			cancel()
			mu.Unlock()
		}
	}
	res.OK = err == nil
	if err != nil {
		res.Error = err.Error()
		if len(res.Error) > 200 {
			res.Error = res.Error[:200]
		}
	}
	a.Log.Printf("%s %s %s: %s", cmd.Cap, cmd.Verb, cmd.Target, map[bool]string{true: "ok", false: res.Error}[res.OK])
	if err := s.send(ctx, res); err != nil {
		a.Log.Printf("could not send the result: %v", err)
	}
}

// update carries out an "update": the new binary in place, the result to labhud, then exec. On a
// refusal the agent goes on as it was.
func (a *Agent) update(ctx context.Context, s *session, up proto.Update) error {
	res := proto.Result{Type: "result", Cmd: up.Cmd}
	path, err := "", errors.New("this agent does not update itself")
	if a.Update != nil {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		path, err = a.Update.Fetch(cctx, up.Version, up.SHA256)
		cancel()
	}
	res.OK = err == nil
	if err != nil {
		res.Error = err.Error()
		a.Log.Printf("update to %s refused: %v", up.Version, err)
		if serr := s.send(ctx, res); serr != nil {
			a.Log.Printf("could not send the result: %v", serr)
		}
		return nil
	}
	a.Log.Printf("updated to %s: starting it", up.Version)
	if serr := s.send(ctx, res); serr != nil {
		a.Log.Printf("could not send the result: %v", serr)
	}
	time.Sleep(500 * time.Millisecond) // the result out before the connection ends with this process
	exec := a.Exec
	if exec == nil {
		// #nosec G204 -- its own binary, put there by Fetch only after both SHA-256 checks
		exec = func(p string) error { return syscall.Exec(p, append([]string{p}, os.Args[1:]...), os.Environ()) }
	}
	if err := exec(path); err != nil {
		return fmt.Errorf("the new binary is in place but did not start: %w (a restart starts it)", err)
	}
	return nil
}

// Emit queues a line for labhud's timeline (a package update that ended, for example). It never
// blocks: with 16 waiting (labhud away for long), the newest is dropped.
func (a *Agent) Emit(text string, bad bool) {
	a.Send(proto.Event{Text: text, Bad: bad})
}

// Send is Emit with what the event is about (a container's update, its crash).
func (a *Agent) Send(ev proto.Event) {
	a.defaults()
	ev.Type = "event"
	select {
	case a.events <- ev:
	default:
		a.Log.Printf("event not sent (labhud away): %s", ev.Text)
	}
}
