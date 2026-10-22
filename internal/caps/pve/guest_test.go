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

	"github.com/Mithrandler/labhud-agent/internal/proto"
)

func guestFake(t *testing.T, denySnap bool) (*PVE, *[]string) {
	var mu sync.Mutex
	calls := &[]string{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		*calls = append(*calls, r.Method+" "+strings.TrimPrefix(r.URL.RequestURI(), "/api2/json")+" "+string(b))
		mu.Unlock()
		p := r.URL.Path
		switch {
		case p == "/api2/json/cluster/status":
			w.Write([]byte(`{"data":[{"type":"node","name":"pve2","local":1}]}`))
		case p == "/api2/json/cluster/resources":
			w.Write([]byte(`{"data":[{"vmid":101,"name":"pbs","type":"qemu","status":"running","node":"pve2"}]}`))
		case p == "/api2/json/nodes/pve2/qemu/101/config":
			w.Write([]byte(`{"data":{"name":"pbs","cores":2,"memory":4096,"cipassword":"hunter2","sshkeys":"ssh-ed25519%20AAA","keyboard":"en-us","net0":"virtio=AA:BB,bridge=vmbr0"}}`))
		case strings.HasSuffix(p, "/snapshot") && r.Method == "GET":
			w.Write([]byte(`{"data":[{"name":"before-upgrade","snaptime":1760000000,"description":"x\u0007y","parent":""},{"name":"current","parent":"before-upgrade"}]}`))
		case strings.HasSuffix(p, "/snapshot") || strings.HasSuffix(p, "/rollback") || r.Method == "DELETE":
			if denySnap {
				w.WriteHeader(403)
				return
			}
			w.Write([]byte(`{"data":"UPID:pve2:0002:snap"}`))
		case strings.Contains(p, "/tasks/"):
			w.Write([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
		case p == "/api2/json/nodes/pve2/tasks":
			w.Write([]byte(`{"data":[{"upid":"UPID:x","type":"qmsnapshot","status":"OK","user":"root@pam","starttime":5,"endtime":9}]}`))
		case p == "/api2/json/nodes/pve2/storage":
			w.Write([]byte(`{"data":[{"storage":"pbs-main"},{"storage":"local"}]}`))
		case strings.HasSuffix(p, "/content"):
			if strings.Contains(p, "pbs-main") {
				w.Write([]byte(`{"data":[{"volid":"pbs-main:backup/vm/101/2026-10-20","size":9,"ctime":20,"format":"pbs-vm","notes":"nightly"}]}`))
			} else {
				w.Write([]byte(`{"data":[{"volid":"local:backup/vzdump-qemu-101.vma.zst","size":5,"ctime":30,"format":"vma.zst","protected":1}]}`))
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
	p.Fill(context.Background(), &proto.State{})
	return p, calls
}

func TestConfigHidesSecrets(t *testing.T) {
	p, _ := guestFake(t, false)
	out, err := p.RunArg(context.Background(), "config", "101", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"hunter2", "AAA"} {
		if strings.Contains(out, leak) {
			t.Errorf("config leaks %q: %s", leak, out)
		}
	}
	if !strings.Contains(out, `"memory"`) || !strings.Contains(out, "en-us") || !strings.Contains(out, "********") {
		t.Errorf("config %s", out)
	}
}

func TestSnapshotsBackupsTasks(t *testing.T) {
	p, _ := guestFake(t, false)
	ctx := context.Background()
	if out, _ := p.RunArg(ctx, "snap-list", "101", ""); !strings.Contains(out, "before-upgrade") || strings.Contains(out, `"current"`) || strings.Contains(out, "\u0007") {
		t.Errorf("snap-list %s", out)
	}
	out, _ := p.RunArg(ctx, "backup-list", "101", "")
	if strings.Index(out, "vzdump") > strings.Index(out, "nightly") { // newest first
		t.Errorf("backup-list not newest first: %s", out)
	}
	if !strings.Contains(out, `"protected":true`) {
		t.Errorf("backup-list %s", out)
	}
	if out, _ := p.RunArg(ctx, "task-list", "101", ""); !strings.Contains(out, "qmsnapshot") || strings.Contains(out, "UPID") {
		t.Errorf("task-list %s", out)
	}
}

func TestSnapshotActions(t *testing.T) {
	p, calls := guestFake(t, false)
	ctx := context.Background()
	for verb, want := range map[string]string{
		"snap-create":   "POST /nodes/pve2/qemu/101/snapshot snapname=s1",
		"snap-rollback": "POST /nodes/pve2/qemu/101/snapshot/s1/rollback",
		"snap-delete":   "DELETE /nodes/pve2/qemu/101/snapshot/s1",
	} {
		if _, err := p.RunArg(ctx, verb, "101", "s1"); err != nil {
			t.Fatalf("%s: %v", verb, err)
		}
		if !strings.Contains(strings.Join(*calls, "\n"), want) {
			t.Errorf("%s: calls %v", verb, *calls)
		}
	}
	if _, err := p.RunArg(ctx, "snap-create", "200", "s1"); err == nil {
		t.Error("a snapshot of a guest that is not on this node")
	}
}

func TestSnapshotWithoutTheRight(t *testing.T) {
	p, _ := guestFake(t, true)
	_, err := p.RunArg(context.Background(), "snap-create", "101", "s1")
	if err == nil || !strings.Contains(err.Error(), "VM.Snapshot") {
		t.Errorf("got %v", err)
	}
}
