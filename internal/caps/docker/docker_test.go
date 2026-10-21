package docker

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Mithrandler/labhud-agent/internal/proto"
)

func fakeEngine(t *testing.T) (*Docker, *[]string) {
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	calls := &[]string{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /containers/json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"Names":["/jellyfin"],"Image":"jellyfin/jellyfin","State":"running","Status":"Up 3 hours (healthy)"},
		                 {"Names":["/old"],"Image":"x","State":"exited","Status":"Exited (0) 2 days ago"}]`))
	})
	mux.HandleFunc("POST /containers/{name}/{verb}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*calls = append(*calls, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		switch r.PathValue("name") {
		case "missing":
			w.WriteHeader(404)
			w.Write([]byte(`{"message":"No such container: missing"}`))
		case "running":
			w.WriteHeader(304)
		default:
			w.WriteHeader(204)
		}
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return New(sock), calls
}

func TestFill(t *testing.T) {
	d, _ := fakeEngine(t)
	var st proto.State
	d.Fill(context.Background(), &st)
	j := st.Containers["jellyfin"]
	if j["state"] != "running" || j["health"] != "healthy" || j["image"] != "jellyfin/jellyfin" {
		t.Errorf("%v", j)
	}
	if _, ok := st.Containers["old"]["health"]; ok || st.Containers["old"]["state"] != "exited" {
		t.Errorf("%v", st.Containers["old"])
	}
}

func TestDo(t *testing.T) {
	d, calls := fakeEngine(t)
	ctx := context.Background()
	if err := d.Do(ctx, "restart", "jellyfin"); err != nil {
		t.Error(err)
	}
	if err := d.Do(ctx, "start", "running"); err != nil {
		t.Errorf("already running is not an error: %v", err)
	}
	if err := d.Do(ctx, "stop", "missing"); err == nil || !strings.Contains(err.Error(), "No such container") {
		t.Errorf("got %v", err)
	}
	want := "POST /containers/jellyfin/restart?t=20,POST /containers/running/start,POST /containers/missing/stop?t=20"
	if got := strings.Join(*calls, ","); got != want {
		t.Errorf("calls %s", got)
	}
}

func TestNoSocket(t *testing.T) {
	if New(filepath.Join(t.TempDir(), "none")) != nil {
		t.Error("found a socket that is not there")
	}
}
