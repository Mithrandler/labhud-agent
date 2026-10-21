package conn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/caps"
	"github.com/Mithrandler/labhud-agent/internal/proto"
)

// pipeStream is a stream that echoes its input in upper case, after a prompt.
type pipeStream struct {
	out     chan []byte
	closed  chan struct{}
	once    sync.Once
	resized chan [2]int
}

func newPipe() *pipeStream {
	p := &pipeStream{out: make(chan []byte, 8), closed: make(chan struct{}), resized: make(chan [2]int, 4)}
	p.out <- []byte("$ ")
	return p
}

func (p *pipeStream) Read(b []byte) (int, error) {
	select {
	case d := <-p.out:
		return copy(b, d), nil
	case <-p.closed:
		return 0, io.EOF
	}
}
func (p *pipeStream) Write(b []byte) (int, error) {
	p.out <- []byte(strings.ToUpper(string(b)))
	return len(b), nil
}
func (p *pipeStream) Resize(c, r int) error { p.resized <- [2]int{c, r}; return nil }
func (p *pipeStream) Close() error          { p.once.Do(func() { close(p.closed) }); return nil }

type termCap struct {
	idle, life time.Duration
	opened     []string
	streams    []*pipeStream
	mu         sync.Mutex
}

func (c *termCap) Name() string                                 { return "terminal" }
func (c *termCap) Fill(context.Context, *proto.State)           {}
func (c *termCap) Do(context.Context, string, string) error     { return errors.New("a stream") }
func (c *termCap) Streams(verb string) bool                     { return verb == "shell" }
func (c *termCap) Limits(string) (time.Duration, time.Duration) { return c.life, c.idle }
func (c *termCap) Open(_ context.Context, verb, target string, cols, rows int) (caps.Stream, error) {
	if target == "broken" {
		return nil, errors.New("the container is not running")
	}
	p := newPipe()
	c.mu.Lock()
	c.opened = append(c.opened, target)
	c.streams = append(c.streams, p)
	c.mu.Unlock()
	return p, nil
}

// readUntil reads frames until `match` says yes, and gives the chunks' text and the end.
func readUntil(t *testing.T, s *srvSession, id string, match func(text string, end *proto.End) bool) (string, *proto.End) {
	t.Helper()
	text := ""
	for i := 0; i < 50; i++ {
		fr, err := s.read()
		if err != nil {
			t.Fatalf("reading: %v (so far %q)", err, text)
		}
		switch fr.Type {
		case "chunk":
			var c proto.Chunk
			json.Unmarshal(fr.Body, &c)
			if c.Cmd == id {
				raw, _ := base64.StdEncoding.DecodeString(c.Data)
				text += string(raw)
			}
		case "end":
			var e proto.End
			json.Unmarshal(fr.Body, &e)
			if e.Cmd == id {
				return text, &e
			}
		}
		if match != nil && match(text, nil) {
			return text, nil
		}
	}
	t.Fatalf("no match, got %q", text)
	return "", nil
}

func runStreams(t *testing.T, tc *termCap, script func(s *srvSession)) {
	f := &fakeLabhud{t: t, allow: proto.Allow{Caps: []string{"terminal"}, Targets: map[string][]string{"terminal": {"web", "web2", "web3", "web4", "broken"}}}}
	f.script = func(s *srvSession) {
		script(s)
		s.send(proto.Bye{Type: "bye", Reason: "removed"})
		time.Sleep(200 * time.Millisecond)
	}
	srv := httptest.NewServer(f)
	defer srv.Close()
	a := newAgent(t, srv.URL, tc)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := a.Run(ctx); !errors.Is(err, ErrRemoved) {
		t.Fatalf("Run: %v", err)
	}
}

func TestShellStreamInputResizeClose(t *testing.T) {
	tc := &termCap{life: time.Minute}
	runStreams(t, tc, func(s *srvSession) {
		id := strings.Repeat("a", 16)
		s.send(proto.Open{Type: "open", Cmd: id, Cap: "terminal", Verb: "shell", Target: "web", Cols: 80, Rows: 24})
		readUntil(t, s, id, func(text string, _ *proto.End) bool { return text == "$ " })
		s.send(proto.StreamIn{Type: "input", Cmd: id, Data: base64.StdEncoding.EncodeToString([]byte("ls\n"))})
		readUntil(t, s, id, func(text string, _ *proto.End) bool { return strings.Contains(text, "LS") })
		s.send(proto.StreamIn{Type: "resize", Cmd: id, Cols: 120, Rows: 40})
		select {
		case r := <-tc.streams[0].resized:
			if r != [2]int{120, 40} {
				t.Errorf("resized %v", r)
			}
		case <-time.After(3 * time.Second):
			t.Error("no resize")
		}
		s.send(proto.StreamIn{Type: "close", Cmd: id})
		if _, e := readUntil(t, s, id, nil); e == nil || e.Reason != "closed" {
			t.Errorf("end: %+v", e)
		}
	})
}

func TestStreamRefusals(t *testing.T) {
	tc := &termCap{life: time.Minute}
	runStreams(t, tc, func(s *srvSession) {
		for i, o := range []struct {
			o    proto.Open
			want string
		}{
			{proto.Open{Cap: "terminal", Verb: "shell", Target: "plex"}, "not allowed"},   // not ticked
			{proto.Open{Cap: "terminal", Verb: "exec", Target: "web"}, "not allowed"},     // no such verb
			{proto.Open{Cap: "terminal", Verb: "shell", Target: "../web"}, "not allowed"}, // not a name
			{proto.Open{Cap: "terminal", Verb: "shell", Target: "broken"}, "not running"}, // the capability says no
			{proto.Open{Cap: "docker", Verb: "follow", Target: "web"}, "not allowed"},     // capability not ticked
		} {
			id := strings.Repeat(string(rune('b'+i)), 16)
			o.o.Type, o.o.Cmd = "open", id
			s.send(o.o)
			_, e := readUntil(t, s, id, nil)
			if e == nil || !strings.Contains(e.Reason, o.want) {
				t.Errorf("%+v: %+v", o.o, e)
			}
		}
		if len(tc.opened) != 0 {
			t.Errorf("opened %v", tc.opened)
		}
	})
}

func TestStreamIdleAndTooMany(t *testing.T) {
	tc := &termCap{life: time.Minute, idle: 1500 * time.Millisecond}
	runStreams(t, tc, func(s *srvSession) {
		ids := []string{}
		for i, name := range []string{"web", "web2", "web3", "web4"} {
			id := strings.Repeat(string(rune('p'+i)), 16)
			ids = append(ids, id)
			s.send(proto.Open{Type: "open", Cmd: id, Cap: "terminal", Verb: "shell", Target: name})
		}
		// the fourth is one too many: it gets its end at once
		_, e := readUntil(t, s, ids[3], nil)
		if e == nil || e.Reason != "too many open" {
			t.Errorf("fourth: %+v", e)
		}
		// the others, left alone, end by the idle limit
		if _, e := readUntil(t, s, ids[0], nil); e == nil || e.Reason != "idle" {
			t.Errorf("first: %+v", e)
		}
	})
}

func TestStreamEndsWithTheLife(t *testing.T) {
	tc := &termCap{life: 1200 * time.Millisecond}
	runStreams(t, tc, func(s *srvSession) {
		id := strings.Repeat("z", 16)
		s.send(proto.Open{Type: "open", Cmd: id, Cap: "terminal", Verb: "shell", Target: "web"})
		if _, e := readUntil(t, s, id, nil); e == nil || e.Reason != "time" {
			t.Errorf("end: %+v", e)
		}
	})
}
