package docker

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var anon = strings.Repeat("ab", 32)

// host is a fake engine with two images (one untagged), an anonymous and a named volume, and
// three networks, one of them with a container.
type host struct {
	mu    sync.Mutex
	calls []string
}

func (h *host) start(t *testing.T) *Docker {
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	j := func(w http.ResponseWriter, v any) { json.NewEncoder(w).Encode(v) }
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.calls = append(h.calls, r.Method+" "+r.URL.Path)
		h.mu.Unlock()
		switch r.Method + " " + r.URL.Path {
		case "GET /system/df":
			j(w, map[string]any{
				"Images": []any{
					map[string]any{"Id": "sha256:aaaaaaaaaaaaaaaa", "RepoTags": []string{"nginx:1"}, "Size": 100, "Containers": 1},
					map[string]any{"Id": "sha256:bbbbbbbbbbbbbbbb", "RepoTags": []string{"<none>:<none>"}, "Size": 900, "Containers": -1},
				},
				"Volumes": []any{
					map[string]any{"Name": anon, "Driver": "local", "UsageData": map[string]any{"Size": 50, "RefCount": 0}},
					map[string]any{"Name": "pgdata", "Driver": "local", "UsageData": map[string]any{"Size": 10, "RefCount": 0}},
					map[string]any{"Name": strings.Repeat("cd", 32), "Driver": "local", "UsageData": map[string]any{"Size": 5, "RefCount": 1}},
				},
			})
		case "GET /networks":
			j(w, []any{map[string]any{"Name": "bridge", "Driver": "bridge", "Scope": "local"},
				map[string]any{"Name": "front", "Driver": "bridge", "Scope": "local"},
				map[string]any{"Name": "old", "Driver": "bridge", "Scope": "local"}})
		case "GET /containers/json":
			j(w, []any{map[string]any{"NetworkSettings": map[string]any{"Networks": map[string]any{"front": map[string]any{}}}}})
		case "POST /networks/prune":
			j(w, map[string]any{"NetworksDeleted": []string{"old"}})
		case "POST /images/prune":
			j(w, map[string]any{"ImagesDeleted": []any{map[string]any{"Deleted": "sha256:bbbb"}}, "SpaceReclaimed": 900})
		default:
			if r.Method == "DELETE" {
				return
			}
			http.NotFound(w, r)
		}
	})
	go http.Serve(l, mux)
	t.Cleanup(func() { l.Close() })
	return New(sock)
}

func TestInventory(t *testing.T) {
	d := (&host{}).start(t)
	out, err := d.Read(context.Background(), "inventory", PruneTarget)
	if err != nil {
		t.Fatal(err)
	}
	var inv Inventory
	if err := json.Unmarshal([]byte(out), &inv); err != nil {
		t.Fatal(err)
	}
	if len(inv.Images) != 2 || inv.Images[0].ID != "bbbbbbbbbbbb" || !inv.Images[0].Dangling || inv.Images[0].Used != 0 {
		t.Errorf("images: %+v", inv.Images)
	}
	if inv.Images[1].Used != 1 || inv.Images[1].Dangling {
		t.Errorf("tagged image: %+v", inv.Images[1])
	}
	if len(inv.Volumes) != 3 || inv.Volumes[0].Name != anon || !inv.Volumes[0].Anonymous || inv.Volumes[1].Anonymous {
		t.Errorf("volumes: %+v", inv.Volumes)
	}
	used := map[string]int{}
	for _, n := range inv.Networks {
		used[n.Name] = n.Used
		if n.Builtin != (n.Name == "bridge") {
			t.Errorf("builtin: %+v", n)
		}
	}
	if used["front"] != 1 || used["old"] != 0 {
		t.Errorf("networks: %+v", inv.Networks)
	}
}

func TestPruneVolumesOnlyAnonymousUnused(t *testing.T) {
	h := &host{}
	d := h.start(t)
	out, err := d.Read(context.Background(), "prune-volumes", PruneTarget)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "1 anonymous volumes") {
		t.Errorf("answer: %q", out)
	}
	var deleted []string
	for _, c := range h.calls {
		if strings.HasPrefix(c, "DELETE ") {
			deleted = append(deleted, c)
		}
	}
	if len(deleted) != 1 || deleted[0] != "DELETE /volumes/"+anon {
		t.Errorf("deleted %v", deleted)
	}
}

func TestPruneNetworksAndDangling(t *testing.T) {
	d := (&host{}).start(t)
	out, err := d.Read(context.Background(), "prune-networks", PruneTarget)
	if err != nil || out != "removed 1 unused networks" {
		t.Errorf("networks: %q %v", out, err)
	}
	out, err = d.Read(context.Background(), "prune-dangling", PruneTarget)
	if err != nil || !strings.Contains(out, "1 untagged layers") {
		t.Errorf("dangling: %q %v", out, err)
	}
}

func TestHostVerbsNeedTheImagesTarget(t *testing.T) {
	d := (&host{}).start(t)
	for _, v := range []string{"inventory", "prune-volumes", "prune-networks", "prune-dangling"} {
		if _, err := d.Read(context.Background(), v, "web"); err == nil {
			t.Errorf("%s ran on a container", v)
		}
		if !d.Reads(v) {
			t.Errorf("%s is not a read verb", v)
		}
		if err := d.Do(context.Background(), v, PruneTarget); err == nil {
			t.Errorf("%s done as an action", v)
		}
	}
}
