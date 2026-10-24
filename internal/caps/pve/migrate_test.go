package pve

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/proto"
)

const (
	fp  = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
	tok = "mig@pve!m=12345678-1234-1234-1234-123456789abc"
)

func TestParsePeers(t *testing.T) {
	good := "pve|192.168.1.101:8006|" + fp + "|" + tok + "|vmbr0|local-lvm"
	ps, err := ParsePeers(good + "; other|pve.lan|" + strings.ToLower(fp) + "|" + tok + "|vmbr1|tank")
	if err != nil || len(ps) != 2 || ps[1].Fingerprint != fp {
		t.Fatalf("%v %v", ps, err)
	}
	if ps, err := ParsePeers(""); err != nil || ps != nil {
		t.Errorf("none: %v %v", ps, err)
	}
	for name, bad := range map[string]string{
		"five fields":   "pve|h|" + fp + "|" + tok + "|vmbr0",
		"upper name":    "PVE|h|" + fp + "|" + tok + "|vmbr0|s",
		"short fp":      "pve|h|AA:BB|" + tok + "|vmbr0|s",
		"no secret":     "pve|h|" + fp + "|mig@pve!m|vmbr0|s",
		"comma in host": "pve|h,fingerprint=x|" + fp + "|" + tok + "|vmbr0|s",
		"comma bridge":  "pve|h|" + fp + "|" + tok + "|vmbr0,x|s",
		"twice":         good + ";" + good,
	} {
		if _, err := ParsePeers(bad); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	p := Peer{Host: "192.168.1.101:8006", Fingerprint: fp, Token: tok}
	if e := p.endpoint(); e != "apitoken=PVEAPIToken="+tok+",host=192.168.1.101,port=8006,fingerprint="+fp {
		t.Errorf("endpoint %q", e)
	}
}

func migrateFake(t *testing.T, exit string, qemu bool) (*PVE, *[]string) {
	var mu sync.Mutex
	calls := &[]string{}
	typ, vmid := "lxc", "113"
	if qemu {
		typ, vmid = "qemu", "101"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		*calls = append(*calls, r.Method+" "+strings.TrimPrefix(r.URL.Path, "/api2/json")+" "+string(b))
		mu.Unlock()
		switch {
		case r.URL.Path == "/api2/json/cluster/status":
			w.Write([]byte(`{"data":[{"type":"node","name":"pve2","local":1}]}`))
		case r.URL.Path == "/api2/json/cluster/resources":
			w.Write([]byte(`{"data":[{"vmid":` + vmid + `,"name":"g","type":"` + typ + `","status":"running","node":"pve2"}]}`))
		case strings.HasSuffix(r.URL.Path, "/remote_migrate"):
			w.Write([]byte(`{"data":"UPID:pve2:0009:move"}`))
		case strings.Contains(r.URL.Path, "/tasks/"):
			if exit == "OK" {
				w.Write([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
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
	p.Client = srv.Client()
	p.Poll = 5 * time.Millisecond
	peers, err := ParsePeers("pve|192.168.1.101|" + fp + "|" + tok + "|vmbr0|local-lvm")
	if err != nil {
		t.Fatal(err)
	}
	p.Peers = peers
	var st proto.State
	p.Fill(context.Background(), &st)
	if len(st.Peers) != 1 || st.Peers[0] != "pve" {
		t.Fatalf("peers in the state: %v", st.Peers)
	}
	return p, calls
}

func form(t *testing.T, calls []string) url.Values {
	for _, c := range calls {
		if strings.HasPrefix(c, "POST ") && strings.Contains(c, "/remote_migrate ") {
			_, body, _ := strings.Cut(c, " ")
			_, body, _ = strings.Cut(body, " ")
			v, err := url.ParseQuery(body)
			if err != nil {
				t.Fatal(err)
			}
			return v
		}
	}
	t.Fatalf("no remote_migrate in %v", calls)
	return nil
}

func TestMigrate(t *testing.T) {
	p, calls := migrateFake(t, "OK", false)
	if !p.TakesArg("migrate") || p.Timeout("migrate") != MigrateTime {
		t.Fatal("migrate takes an argument and its time")
	}
	if _, err := p.RunArg(context.Background(), "migrate", "113", "pve:online"); err != nil {
		t.Fatal(err)
	}
	f := form(t, *calls)
	if f.Get("target-vmid") != "113" || f.Get("target-bridge") != "vmbr0" || f.Get("target-storage") != "local-lvm" ||
		f.Get("restart") != "1" || f.Get("online") != "" || f.Get("delete") != "" ||
		!strings.Contains(f.Get("target-endpoint"), "fingerprint="+fp) {
		t.Errorf("an LXC moves with a restart and keeps the original: %v", f)
	}
	p, calls = migrateFake(t, "OK", false)
	if _, err := p.RunArg(context.Background(), "migrate", "113", "pve:offline:913"); err != nil {
		t.Fatal(err)
	}
	if f := form(t, *calls); f.Get("target-vmid") != "913" {
		t.Errorf("a number taken on the other node: %v", f)
	}
	p, calls = migrateFake(t, "OK", true)
	if _, err := p.RunArg(context.Background(), "migrate", "101", "pve:online"); err != nil {
		t.Fatal(err)
	}
	if f := form(t, *calls); f.Get("online") != "1" || f.Get("restart") != "" {
		t.Errorf("a VM moves live: %v", f)
	}
	p, calls = migrateFake(t, "OK", true)
	if _, err := p.RunArg(context.Background(), "migrate", "101", "pve:offline"); err != nil {
		t.Fatal(err)
	}
	if f := form(t, *calls); f.Get("online") != "" {
		t.Errorf("offline: %v", f)
	}
}

func TestMigrateRefused(t *testing.T) {
	p, calls := migrateFake(t, "OK", false)
	if _, err := p.RunArg(context.Background(), "migrate", "113", "nowhere:online"); err == nil || !strings.Contains(err.Error(), "no peer") {
		t.Errorf("a peer the host does not have: %v", err)
	}
	for _, c := range *calls {
		if strings.Contains(c, "remote_migrate") {
			t.Errorf("nothing may be sent: %v", *calls)
		}
	}
	// a failed task: the token of the target must not come back in the message
	p, _ = migrateFake(t, "migration aborted: could not log in with PVEAPIToken="+tok, false)
	_, err := p.RunArg(context.Background(), "migrate", "113", "pve:offline")
	if err == nil || strings.Contains(err.Error(), "12345678") {
		t.Errorf("the failure keeps the secret out: %v", err)
	}
}
