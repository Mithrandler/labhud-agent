package docker

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/Mithrandler/labhud-agent/internal/allow"
)

const engineAnswer = `{
 "cpu_stats":{"cpu_usage":{"total_usage":300},"system_cpu_usage":2000,"online_cpus":4},
 "precpu_stats":{"cpu_usage":{"total_usage":100},"system_cpu_usage":1000},
 "memory_stats":{"usage":1000,"limit":4000,"stats":{"inactive_file":200}},
 "networks":{"eth0":{"rx_bytes":10,"tx_bytes":20},"eth1":{"rx_bytes":1,"tx_bytes":2}},
 "pids_stats":{"current":7},
 "blkio_stats":{"io_service_bytes_recursive":[{"op":"Read","value":5},{"op":"Write","value":9},{"op":"Read","value":1},{"op":"Total","value":15}]}
}`

func statsEngine(t *testing.T) *Docker {
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /containers/{name}/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("name") == "gone" {
			w.WriteHeader(404)
			w.Write([]byte(`{"message":"No such container: gone"}`))
			return
		}
		w.Write([]byte(engineAnswer))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return New(sock)
}

func TestStatsIsARead(t *testing.T) {
	d := statsEngine(t)
	if !d.Reads("stats") {
		t.Error("stats must be a read verb")
	}
	if err := d.Do(context.Background(), "stats", "web"); err == nil {
		t.Error("stats is read, not done")
	}
	found := false
	for _, v := range allow.Verbs["docker"] {
		found = found || v == "stats"
	}
	if !found {
		t.Error("stats is not in the allowed verbs")
	}
}

func TestStatsNow(t *testing.T) {
	d := statsEngine(t)
	out, err := d.Read(context.Background(), "stats", "web")
	if err != nil {
		t.Fatal(err)
	}
	var n Now
	if err := json.Unmarshal([]byte(out), &n); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	// cpu: (300-100)/(2000-1000) * 4 cores * 100 = 80 %; memory without the page cache: 1000-200
	if n.CPU != 80 || n.Mem != 800 || n.MemLimit != 4000 || n.MemPct != 20 {
		t.Errorf("cpu/mem: %+v", n)
	}
	if n.NetRx != 11 || n.NetTx != 22 || n.BlockRead != 6 || n.BlockWrite != 9 || n.Pids != 7 {
		t.Errorf("net/block/pids: %+v", n)
	}
}

func TestStatsOfAContainerThatIsNotThere(t *testing.T) {
	d := statsEngine(t)
	if _, err := d.Read(context.Background(), "stats", "gone"); err == nil {
		t.Error("a missing container has no numbers")
	}
}
