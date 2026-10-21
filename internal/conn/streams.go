package conn

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/caps"
	"github.com/Mithrandler/labhud-agent/internal/proto"
)

const (
	// MaxStreams: how many may be open on one connection (a log and a terminal, and one more)
	MaxStreams = 3
	// chunkSize: output goes out in pieces of at most this many bytes (before base64)
	chunkSize = 8 << 10
	// maxInput: one input message, in bytes (a paste)
	maxInput = 16 << 10
)

type openStream struct {
	st     caps.Stream
	cancel context.CancelCauseFunc
	last   atomic.Int64 // unix nanoseconds of the last input, for the idle limit
	closed atomic.Bool
}

// streamTable is the streams open on one connection, by labhud's id for them.
type streamTable struct {
	mu sync.Mutex
	m  map[string]*openStream
}

func (t *streamTable) add(id string, o *openStream) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[string]*openStream{}
	}
	if _, dup := t.m[id]; dup || len(t.m) >= MaxStreams {
		return false
	}
	t.m[id] = o
	return true
}

func (t *streamTable) get(id string) *openStream {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.m[id]
}

func (t *streamTable) drop(id string) {
	t.mu.Lock()
	delete(t.m, id)
	t.mu.Unlock()
}

func (t *streamTable) closeAll() {
	t.mu.Lock()
	all := t.m
	t.m = nil
	t.mu.Unlock()
	for _, o := range all {
		o.cancel(errors.New("closed"))
		o.st.Close()
	}
}

// in hands labhud's input, resize or close to the stream; for an id that is not open it does nothing.
func (t *streamTable) in(m proto.StreamIn) {
	o := t.get(m.Cmd)
	if o == nil {
		return
	}
	switch m.Type {
	case "close":
		o.cancel(errors.New("closed"))
	case "resize":
		if m.Cols > 0 && m.Cols <= 500 && m.Rows > 0 && m.Rows <= 200 {
			o.st.Resize(m.Cols, m.Rows)
		}
	case "input":
		raw, err := base64.StdEncoding.DecodeString(m.Data)
		if err != nil || len(raw) > maxInput {
			return
		}
		o.last.Store(time.Now().UnixNano())
		o.st.Write(raw) // a log refuses it; a shell takes it
	}
}

// openStream opens what labhud asked for, after the same check as a command's, and pumps its
// output to labhud until it ends, the time is up, or labhud closes it. The one answer to a refusal
// or an ending is an `end`.
func (a *Agent) openStream(ctx context.Context, s *session, o proto.Open) {
	end := func(reason string) {
		if len(reason) > 200 {
			reason = reason[:200]
		}
		if err := s.send(ctx, proto.End{Type: "end", Cmd: o.Cmd, Reason: reason}); err != nil {
			a.Log.Printf("could not send an end: %v", err)
		}
	}
	err := a.Allow.Check(o.Cap, o.Verb, o.Target)
	var sr caps.Streamer
	if err == nil {
		for _, c := range a.Caps {
			if x, ok := c.(caps.Streamer); ok && c.Name() == o.Cap && x.Streams(o.Verb) {
				sr = x
			}
		}
		if sr == nil {
			err = errors.New("this host has no " + o.Cap + " " + o.Verb)
		}
	}
	if err != nil {
		a.Log.Printf("%s %s %s: refused: %v", o.Cap, o.Verb, o.Target, err)
		end(err.Error())
		return
	}
	life, idle := sr.Limits(o.Verb)
	sctx, cancel := context.WithCancelCause(ctx)
	st, err := sr.Open(sctx, o.Verb, o.Target, o.Cols, o.Rows)
	if err != nil {
		cancel(nil)
		a.Log.Printf("%s %s %s: %v", o.Cap, o.Verb, o.Target, err)
		end(err.Error())
		return
	}
	ost := &openStream{st: st, cancel: cancel}
	ost.last.Store(time.Now().UnixNano())
	if !s.streams.add(o.Cmd, ost) {
		cancel(nil)
		st.Close()
		end("too many open")
		return
	}
	a.Log.Printf("%s %s %s: open", o.Cap, o.Verb, o.Target) // never what went through it
	go func() {
		reason := a.pump(sctx, s, o.Cmd, ost, life, idle)
		s.streams.drop(o.Cmd)
		ost.closed.Store(true)
		cancel(nil)
		st.Close()
		a.Log.Printf("%s %s %s: closed (%s)", o.Cap, o.Verb, o.Target, reason)
		end(reason)
	}()
}

// pump sends the stream's output as chunks and says why it stopped.
func (a *Agent) pump(ctx context.Context, s *session, id string, o *openStream, life, idle time.Duration) string {
	done := make(chan string, 2)
	go func() { // the clock: the life, the idle time, or labhud's close
		t := time.NewTicker(time.Second)
		defer t.Stop()
		start := time.Now()
		for {
			select {
			case <-ctx.Done():
				if c := context.Cause(ctx); c != nil && c.Error() != "context canceled" {
					done <- c.Error()
				} else {
					done <- "closed"
				}
				return
			case <-t.C:
				if life > 0 && time.Since(start) > life {
					done <- "time"
					return
				}
				if idle > 0 && time.Since(time.Unix(0, o.last.Load())) > idle {
					done <- "idle"
					return
				}
			}
		}
	}()
	out := make(chan string, 1)
	go func() {
		buf := make([]byte, chunkSize)
		for {
			n, err := o.st.Read(buf)
			if n > 0 {
				msg := proto.Chunk{Type: "chunk", Cmd: id, Data: base64.StdEncoding.EncodeToString(buf[:n])}
				if serr := s.send(ctx, msg); serr != nil {
					out <- "the connection ended"
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					out <- "ended"
				} else {
					out <- "ended: " + err.Error()
				}
				return
			}
		}
	}()
	select {
	case r := <-done:
		o.st.Close() // unblocks the reader
		return r
	case r := <-out:
		return r
	}
}
