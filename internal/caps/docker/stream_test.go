package docker

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// frameOf is one piece of Docker's multiplexed log stream.
func frameOf(stream byte, text string) []byte {
	h := make([]byte, 8)
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:], uint32(len(text)))
	return append(h, text...)
}

func TestDemuxerJoinsThePieces(t *testing.T) {
	var in []byte
	in = append(in, frameOf(1, "hello ")...)
	in = append(in, frameOf(2, "world\n")...)
	got, err := io.ReadAll(&demuxer{r: strings.NewReader(string(in))})
	if err != nil || string(got) != "hello world\n" {
		t.Errorf("%q %v", got, err)
	}
	if _, err := io.ReadAll(&demuxer{r: strings.NewReader("not a log stream at all")}); err == nil {
		t.Error("a stream that is not one was read")
	}
}

// term is a fake engine: a running container "web", a log that gives two lines and waits, and
// an exec whose start is taken over and echoes what it is sent.
type term struct {
	mu      sync.Mutex
	calls   []string
	resized string
	typed   chan string
}

func (e *term) start(t *testing.T, running bool) *Docker {
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	e.typed = make(chan string, 4)
	mux := http.NewServeMux()
	note := func(r *http.Request) {
		e.mu.Lock()
		e.calls = append(e.calls, r.Method+" "+r.URL.Path)
		e.mu.Unlock()
	}
	mux.HandleFunc("GET /containers/{n}/json", func(w http.ResponseWriter, r *http.Request) {
		note(r)
		w.Write([]byte(`{"Config":{"Tty":false},"State":{"Running":` + map[bool]string{true: "true", false: "false"}[running] + `}}`))
	})
	mux.HandleFunc("GET /containers/{n}/logs", func(w http.ResponseWriter, r *http.Request) {
		note(r)
		w.Write(frameOf(1, "first\n"))
		w.(http.Flusher).Flush()
		w.Write(frameOf(2, "second\n"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	mux.HandleFunc("POST /containers/{n}/exec", func(w http.ResponseWriter, r *http.Request) {
		note(r)
		b, _ := io.ReadAll(r.Body)
		e.typed <- "create " + string(b)
		w.Write([]byte(`{"Id":"exec1"}`))
	})
	mux.HandleFunc("POST /exec/{id}/resize", func(w http.ResponseWriter, r *http.Request) {
		note(r)
		e.mu.Lock()
		e.resized = r.URL.RawQuery
		e.mu.Unlock()
	})
	mux.HandleFunc("POST /exec/{id}/start", func(w http.ResponseWriter, r *http.Request) {
		note(r)
		io.Copy(io.Discard, r.Body)
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		rw.WriteString("HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
		rw.WriteString("$ ")
		rw.Flush()
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			e.typed <- "typed " + line
			rw.WriteString("echo " + line)
			rw.Flush()
		}
	})
	go http.Serve(l, mux)
	t.Cleanup(func() { l.Close() })
	return New(sock)
}

func readSome(t *testing.T, s interface{ Read([]byte) (int, error) }, want string) {
	t.Helper()
	got := ""
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 256)
		for !strings.Contains(got, want) {
			n, err := s.Read(buf)
			got += string(buf[:n])
			if err != nil {
				break
			}
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
	if !strings.Contains(got, want) {
		t.Fatalf("read %q, wanted %q", got, want)
	}
}

func TestFollowGivesTheLogAndIsReadOnly(t *testing.T) {
	d := (&term{}).start(t, true)
	st, err := d.Open(context.Background(), "follow", "web", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	readSome(t, st, "first\nsecond\n")
	if _, err := st.Write([]byte("rm -rf /\n")); err == nil {
		t.Error("a log took input")
	}
	if !d.Streams("follow") || d.Streams("shell") {
		t.Error("docker streams exactly follow")
	}
	if err := d.Do(context.Background(), "follow", "web"); err == nil {
		t.Error("follow done as an action")
	}
}

func TestShellEchoesAndResizes(t *testing.T) {
	e := &term{}
	d := e.start(t, true)
	tm := &Terminal{D: d}
	st, err := tm.Open(context.Background(), "shell", "web", 100, 30)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if c := <-e.typed; !strings.Contains(c, `"Tty":true`) || !strings.Contains(c, "exec bash || exec sh") {
		t.Errorf("exec made as %s", c)
	}
	readSome(t, st, "$ ")
	st.Write([]byte("ls\n"))
	if c := <-e.typed; c != "typed ls\n" {
		t.Errorf("the container got %q", c)
	}
	readSome(t, st, "echo ls")
	if err := st.Resize(120, 40); err != nil {
		t.Error(err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !strings.Contains(e.resized, "h=40") || !strings.Contains(e.resized, "w=120") {
		t.Errorf("resize: %q", e.resized)
	}
}

func TestShellNeedsARunningContainer(t *testing.T) {
	d := (&term{}).start(t, false)
	if _, err := (&Terminal{D: d}).Open(context.Background(), "shell", "web", 80, 24); err == nil ||
		!strings.Contains(err.Error(), "not running") {
		t.Errorf("err: %v", err)
	}
	if (&Terminal{D: d}).Streams("follow") {
		t.Error("the terminal streams only shell")
	}
}
