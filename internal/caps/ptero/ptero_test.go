package ptero

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mithrandler/labhud-agent/internal/proto"
)

func fake(t *testing.T) (*Ptero, *[]string) {
	calls := &[]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ptlc_key" {
			w.WriteHeader(401)
			w.Write([]byte(`{"errors":[{"detail":"Unauthenticated."}]}`))
			return
		}
		b, _ := io.ReadAll(r.Body)
		*calls = append(*calls, r.Method+" "+r.URL.RequestURI()+" "+string(b))
		switch r.URL.Path {
		case "/api/client":
			w.Write([]byte(`{"data":[{"attributes":{"identifier":"1a2b3c4d","name":"Valheim"}},
			                        {"attributes":{"identifier":"5e6f7a8b","name":"Old","is_suspended":true}}]}`))
		case "/api/client/servers/1a2b3c4d/resources":
			w.Write([]byte(`{"attributes":{"current_state":"running","resources":{"memory_bytes":2048,"cpu_absolute":12.34,"disk_bytes":9,"uptime":60000}}}`))
		case "/api/client/servers/1a2b3c4d/power":
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"errors":[{"detail":"The requested resource could not be found."}]}`))
		}
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL+"/", "ptlc_key", ""), calls
}

func TestFill(t *testing.T) {
	p, calls := fake(t)
	var st proto.State
	p.Fill(context.Background(), &st)
	v := st.Servers["1a2b3c4d"]
	if v["name"] != "Valheim" || v["state"] != "running" || v["cpu"] != 12.3 || v["uptime"] != int64(60) {
		t.Errorf("%v", v)
	}
	if st.Servers["5e6f7a8b"]["state"] != "suspended" {
		t.Errorf("%v", st.Servers["5e6f7a8b"])
	}
	n := len(*calls)
	p.Fill(context.Background(), &st) // cached
	if len(*calls) != n {
		t.Error("read again within Every")
	}
}

func TestPower(t *testing.T) {
	p, calls := fake(t)
	if err := p.Do(context.Background(), "restart", "1a2b3c4d"); err != nil {
		t.Fatal(err)
	}
	if last := (*calls)[len(*calls)-1]; last != `POST /api/client/servers/1a2b3c4d/power {"signal":"restart"}` {
		t.Errorf("%s", last)
	}
	if err := p.Do(context.Background(), "start", "deadbeef"); err == nil || !strings.Contains(err.Error(), "could not be found") {
		t.Errorf("got %v", err)
	}
	if err := p.Do(context.Background(), "kill", "1a2b3c4d"); err == nil {
		t.Error("kill is not a verb")
	}
	p.Key = "wrong"
	if err := p.Do(context.Background(), "start", "1a2b3c4d"); err == nil || !strings.Contains(err.Error(), "Unauthenticated") {
		t.Errorf("got %v", err)
	}
}

// A self-signed panel: the pinned certificate is accepted, any other refused before the key is sent.
func TestPin(t *testing.T) {
	got := ""
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	pin := hex.EncodeToString(sum[:])

	ok := New(srv.URL, "ptlc_key", pin)
	if err := ok.call(context.Background(), "GET", "", nil, nil); err != nil || got != "Bearer ptlc_key" {
		t.Fatalf("pinned: %v %q", err, got)
	}
	got = ""
	bad := New(srv.URL, "ptlc_key", strings.Repeat("0", 64))
	if err := bad.call(context.Background(), "GET", "", nil, nil); err == nil || !strings.Contains(err.Error(), "pinned") || got != "" {
		t.Fatalf("other pin: %v, key seen %q", err, got)
	}
	if err := New(srv.URL, "ptlc_key", "").call(context.Background(), "GET", "", nil, nil); err == nil {
		t.Fatal("no pin: a self-signed panel must fail the system roots")
	}
}
