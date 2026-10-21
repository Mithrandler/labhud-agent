package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/caps"
	"github.com/Mithrandler/labhud-agent/internal/proto"
)

// What labhud's live log and terminal are made of (caps.Streamer): `follow` on a ticked container
// (docker's own capability) and `shell` on one ticked for the terminal capability (Terminal,
// which exists only when the agent was started with LABHUD_AGENT_TERMINAL=on).

const (
	// FollowLife: a live log closes by itself after this long
	FollowLife = 10 * time.Minute
	// ShellLife and ShellIdle: a terminal closes after this long, or after this long without a key
	ShellLife = 15 * time.Minute
	ShellIdle = 3 * time.Minute
	// followTail: the lines a live log starts with
	followTail = 50
)

func (d *Docker) Streams(verb string) bool { return verb == "follow" }

func (d *Docker) Limits(verb string) (time.Duration, time.Duration) { return FollowLife, 0 }

// follow is a container's log being followed: output only.
type follow struct {
	body   io.ReadCloser
	r      io.Reader
	cancel context.CancelFunc
}

func (f *follow) Read(p []byte) (int, error)  { return f.r.Read(p) }
func (f *follow) Write(p []byte) (int, error) { return 0, errors.New("a log takes no input") }
func (f *follow) Resize(int, int) error       { return nil }
func (f *follow) Close() error                { f.cancel(); return f.body.Close() }

func (d *Docker) Open(ctx context.Context, verb, target string, cols, rows int) (caps.Stream, error) {
	if verb != "follow" {
		return nil, fmt.Errorf("docker: no stream %q", verb)
	}
	var info struct{ Config struct{ Tty bool } }
	if err := d.call(ctx, "GET", "/containers/"+url.PathEscape(target)+"/json", &info); err != nil {
		return nil, err
	}
	cctx, cancel := context.WithCancel(ctx)
	req, err := http.NewRequestWithContext(cctx, "GET", fmt.Sprintf(
		"http://docker/containers/%s/logs?stdout=1&stderr=1&follow=1&tail=%d", url.PathEscape(target), followTail), nil)
	if err != nil {
		cancel()
		return nil, err
	}
	r, err := d.c.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}
	if r.StatusCode >= 300 {
		r.Body.Close()
		cancel()
		return nil, fmt.Errorf("docker: HTTP %d", r.StatusCode)
	}
	var rd io.Reader = r.Body
	if !info.Config.Tty {
		rd = &demuxer{r: r.Body}
	}
	return &follow{body: r.Body, r: rd, cancel: cancel}, nil
}

// demuxer reads Docker's multiplexed log stream (an 8-byte header, then the bytes) as one stream.
type demuxer struct {
	r    io.Reader
	left int
}

func (m *demuxer) Read(p []byte) (int, error) {
	for m.left == 0 {
		var h [8]byte
		if _, err := io.ReadFull(m.r, h[:]); err != nil {
			return 0, err
		}
		if h[0] > 2 || h[1] != 0 || h[2] != 0 || h[3] != 0 {
			return 0, errors.New("not a log stream")
		}
		m.left = int(binary.BigEndian.Uint32(h[4:8]))
	}
	if len(p) > m.left {
		p = p[:m.left]
	}
	n, err := m.r.Read(p)
	m.left -= n
	return n, err
}

// Terminal is the terminal capability: a shell in a ticked container, through `docker exec` with
// a TTY on the engine's socket. Off unless New was called (LABHUD_AGENT_TERMINAL=on).
type Terminal struct{ D *Docker }

func (t *Terminal) Name() string                       { return "terminal" }
func (t *Terminal) Fill(context.Context, *proto.State) {}
func (t *Terminal) Do(context.Context, string, string) error {
	return errors.New("terminal: a shell is a stream")
}
func (t *Terminal) Streams(verb string) bool                     { return verb == "shell" }
func (t *Terminal) Limits(string) (time.Duration, time.Duration) { return ShellLife, ShellIdle }

// shell is the hijacked connection of an exec.
type shell struct {
	d    *Docker
	id   string
	conn net.Conn
	r    *bufio.Reader
	once sync.Once
}

func (s *shell) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *shell) Write(p []byte) (int, error) { return s.conn.Write(p) }
func (s *shell) Close() error                { var err error; s.once.Do(func() { err = s.conn.Close() }); return err }

func (s *shell) Resize(cols, rows int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.d.post(ctx, "POST", fmt.Sprintf("/exec/%s/resize?h=%d&w=%d", s.id, rows, cols), nil, nil)
}

// post is call with a JSON body.
func (d *Docker) post(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	r, err := d.c.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if r.StatusCode >= 300 {
		var e struct{ Message string }
		if json.Unmarshal(b, &e) == nil && e.Message != "" {
			return fmt.Errorf("docker: %s", e.Message)
		}
		return fmt.Errorf("docker: HTTP %d", r.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// shellCommand: bash when the container has it, else sh. A fixed line, nothing of labhud's.
var shellCommand = []string{"sh", "-c", "command -v bash >/dev/null 2>&1 && exec bash || exec sh"}

func (t *Terminal) Open(ctx context.Context, verb, target string, cols, rows int) (caps.Stream, error) {
	if verb != "shell" {
		return nil, fmt.Errorf("terminal: no stream %q", verb)
	}
	d := t.D
	var info struct{ State struct{ Running bool } }
	if err := d.call(ctx, "GET", "/containers/"+url.PathEscape(target)+"/json", &info); err != nil {
		return nil, err
	}
	if !info.State.Running {
		return nil, errors.New("the container is not running")
	}
	var made struct{ Id string }
	if err := d.post(ctx, "POST", "/containers/"+url.PathEscape(target)+"/exec", map[string]any{
		"AttachStdin": true, "AttachStdout": true, "AttachStderr": true, "Tty": true,
		"Env": []string{"TERM=xterm-256color"}, "Cmd": shellCommand}, &made); err != nil {
		return nil, err
	}
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "unix", d.socket)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]any{"Detach": false, "Tty": true})
	req := fmt.Sprintf("POST /exec/%s/start HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\n"+
		"Connection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: %d\r\n\r\n%s", made.Id, len(body), body)
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || (resp.StatusCode != http.StatusSwitchingProtocols && resp.StatusCode != http.StatusOK) {
		conn.Close()
		if err == nil {
			err = fmt.Errorf("docker: HTTP %d", resp.StatusCode)
		}
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	sh := &shell{d: d, id: made.Id, conn: conn, r: br}
	if cols > 0 && rows > 0 {
		sh.Resize(cols, rows)
	}
	return sh, nil
}
