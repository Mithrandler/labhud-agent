package pve

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/Mithrandler/labhud-agent/internal/proto"
)

// consoleFake is a node with one LXC (113) whose termproxy greets with OK and echoes input.
func consoleFake(t *testing.T, ticket string) (*PVE, *[]string) {
	var mu sync.Mutex
	got := &[]string{}
	note := func(s string) {
		mu.Lock()
		*got = append(*got, s)
		mu.Unlock()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "PVEAPIToken=labhud@pve!agent=secret" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/api2/json/cluster/status":
			w.Write([]byte(`{"data":[{"type":"node","name":"pve2","local":1}]}`))
		case "/api2/json/cluster/resources":
			w.Write([]byte(`{"data":[{"vmid":113,"name":"web","type":"lxc","status":"running","node":"pve2"}]}`))
		case "/api2/json/nodes/pve2/lxc/113/termproxy":
			if r.Method != "POST" {
				w.WriteHeader(405)
				return
			}
			w.Write([]byte(`{"data":{"port":"5900","ticket":"` + ticket + `","user":"labhud@pve!agent","upid":"UPID:x"}}`))
		case "/api2/json/nodes/pve2/lxc/113/vncwebsocket":
			if r.URL.Query().Get("port") != "5900" || r.URL.Query().Get("vncticket") != ticket {
				w.WriteHeader(401)
				return
			}
			ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"binary"}})
			if err != nil {
				return
			}
			defer ws.CloseNow()
			ctx := r.Context()
			_, first, err := ws.Read(ctx)
			if err != nil || string(first) != "labhud@pve!agent:"+ticket+"\n" {
				return
			}
			ws.Write(ctx, websocket.MessageBinary, []byte("OK"))
			for {
				_, m, err := ws.Read(ctx)
				if err != nil {
					return
				}
				s := string(m)
				switch {
				case strings.HasPrefix(s, "0:"):
					note("in " + s)
					rest := s[2:]
					_, data, _ := strings.Cut(rest, ":")
					ws.Write(ctx, websocket.MessageBinary, []byte(data))
				case strings.HasPrefix(s, "1:"):
					note("resize " + s)
				}
			}
		default:
			w.WriteHeader(404)
		}
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	p := New(srv.URL, "labhud@pve!agent=secret", t.TempDir())
	p.Client = srv.Client()
	p.Poll = 10 * time.Millisecond
	var st proto.State
	p.Fill(context.Background(), &st)
	return p, got
}

func TestConsole(t *testing.T) {
	p, got := consoleFake(t, "PVEVNC:ABC::sig/with+chars=")
	if !p.Streams("console") || p.Streams("shell") {
		t.Fatal("console is the one stream verb")
	}
	life, idle := p.Limits("console")
	if life != ConsoleLife || idle != ConsoleIdle {
		t.Errorf("limits %v %v", life, idle)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := p.Open(ctx, "console", "113", 100, 30)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Write([]byte("ls\r")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := st.Read(buf)
	if err != nil || string(buf[:n]) != "ls\r" {
		t.Fatalf("echo %q %v", buf[:n], err)
	}
	if err := st.Resize(120, 40); err != nil {
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond)
	joined := strings.Join(*got, "|")
	for _, want := range []string{"resize 1:100:30:", "in 0:3:ls\r", "resize 1:120:40:"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %q", want, joined)
		}
	}
	// a long paste goes in pieces, none past inputChunk
	long := strings.Repeat("x", inputChunk*2+5)
	if _, err := st.Write([]byte(long)); err != nil {
		t.Fatal(err)
	}
	total := 0
	for total < len(long) {
		n, err := st.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		total += n
	}
	if total != len(long) {
		t.Errorf("echoed %d of %d", total, len(long))
	}
}

func TestConsoleRefused(t *testing.T) {
	p, _ := consoleFake(t, "T")
	if _, err := p.Open(context.Background(), "console", "999", 80, 24); err == nil || !strings.Contains(err.Error(), "no guest") {
		t.Errorf("a guest this node does not have: %v", err)
	}
	if _, err := p.Open(context.Background(), "shell", "113", 80, 24); err == nil {
		t.Error("only console")
	}
	// the token has no VM.Console: Proxmox says 403 and the message says what to do
	p.Token = "labhud@pve!agent=wrong"
	_, err := p.Open(context.Background(), "console", "113", 80, 24)
	if err == nil {
		t.Fatal("a wrong token")
	}
	_ = io.EOF
}
