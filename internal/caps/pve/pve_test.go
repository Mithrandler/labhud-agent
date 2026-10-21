package pve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/proto"
)

func fake(t *testing.T, exit string) (*PVE, *[]string) {
	var mu sync.Mutex
	calls := &[]string{}
	polls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "PVEAPIToken=labhud@pve!agent=secret" {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		*calls = append(*calls, r.Method+" "+strings.TrimPrefix(r.URL.Path, "/api2/json"))
		mu.Unlock()
		switch {
		case r.URL.Path == "/api2/json/cluster/status":
			w.Write([]byte(`{"data":[{"type":"cluster","name":"c"},{"type":"node","name":"pve2","local":1},{"type":"node","name":"pve","local":0}]}`))
		case r.URL.Path == "/api2/json/cluster/resources":
			w.Write([]byte(`{"data":[
			 {"vmid":101,"name":"pbs","type":"qemu","status":"running","node":"pve2","cpu":0.012,"mem":512,"maxmem":1024,"maxdisk":100,"uptime":60,"tags":"Infra;db"},
			 {"vmid":113,"name":"web","type":"lxc","status":"running","node":"pve2","cpu":0,"mem":0,"maxmem":0,"maxdisk":50,"disk":20},
			 {"vmid":200,"name":"other","type":"qemu","status":"stopped","node":"pve"}]}`))
		case strings.HasSuffix(r.URL.Path, "/status/shutdown"):
			w.Write([]byte(`{"data":"UPID:pve2:0001:shutdown"}`))
		case strings.Contains(r.URL.Path, "/tasks/"):
			polls++
			if polls < 2 {
				w.Write([]byte(`{"data":{"status":"running"}}`))
			} else {
				w.Write([]byte(`{"data":{"status":"stopped","exitstatus":"` + exit + `"}}`))
			}
		default:
			w.WriteHeader(404)
		}
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	p := New(srv.URL, "labhud@pve!agent=secret", t.TempDir())
	p.Client = srv.Client() // trusts the test certificate, as the cluster CA would
	p.Poll = 10 * time.Millisecond
	return p, calls
}

func TestFill(t *testing.T) {
	p, _ := fake(t, "OK")
	var st proto.State
	p.Fill(context.Background(), &st)
	if st.Node != "pve2" {
		t.Errorf("node %q", st.Node)
	}
	if len(st.Guests) != 2 {
		t.Fatalf("guests %v (another node's guest must not be there)", st.Guests)
	}
	g := st.Guests["101"]
	if g["name"] != "pbs" || g["running"] != true || g["cpu"] != 1.2 || g["mem"] != 50.0 ||
		strings.Join(g["tags"].([]string), ",") != "db,infra" {
		t.Errorf("101: %v", g)
	}
	if st.Guests["113"]["mem"] != nil || st.Guests["113"]["disk_used"] != 20.0 {
		t.Errorf("113: %v", st.Guests["113"])
	}
}

func TestShutdownWaitsForTheTask(t *testing.T) {
	p, calls := fake(t, "OK")
	p.Fill(context.Background(), &proto.State{})
	if err := p.Do(context.Background(), "shutdown", "101"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(*calls, ","), "POST /nodes/pve2/qemu/101/status/shutdown") {
		t.Errorf("calls %v", *calls)
	}
}

func TestTaskFailed(t *testing.T) {
	p, _ := fake(t, "VM quit/powerdown failed")
	p.Fill(context.Background(), &proto.State{})
	if err := p.Do(context.Background(), "shutdown", "101"); err == nil || !strings.Contains(err.Error(), "powerdown failed") {
		t.Errorf("got %v", err)
	}
}

func TestRefused(t *testing.T) {
	p, _ := fake(t, "OK")
	p.Fill(context.Background(), &proto.State{})
	if err := p.Do(context.Background(), "shutdown", "200"); err == nil {
		t.Error("acted on another node's guest")
	}
	if err := p.Do(context.Background(), "stop", "101"); err == nil {
		t.Error("a hard stop")
	}
	p.Token = "wrong"
	if err := p.Do(context.Background(), "start", "101"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("got %v", err)
	}
}

func TestNoToken(t *testing.T) {
	if New("https://localhost:8006", "", "/") != nil {
		t.Error("a capability without a token")
	}
}
