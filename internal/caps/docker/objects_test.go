package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func tarOf(entries map[string]string, dirs ...string) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, d := range dirs {
		tw.WriteHeader(&tar.Header{Name: d, Typeflag: tar.TypeDir, Mode: 0o755, ModTime: time.Unix(1700000000, 0)})
	}
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	// stable: the map order is not
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	for _, n := range names {
		tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(entries[n])), ModTime: time.Unix(1700000000, 0)})
		tw.Write([]byte(entries[n]))
	}
	tw.Close()
	return buf.Bytes()
}

type objectsEngine struct {
	d       *Docker
	mu      sync.Mutex
	calls   []string
	binds   []string
	removed []string
	archive map[string][]byte // the path asked (inside the container) -> the tar
}

func newObjectsEngine(t *testing.T) *objectsEngine {
	e := &objectsEngine{archive: map[string][]byte{}}
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	note := func(r *http.Request) {
		e.mu.Lock()
		e.calls = append(e.calls, r.Method+" "+r.URL.RequestURI())
		e.mu.Unlock()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /images/json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"RepoTags":["big:1"],"Size":900},{"RepoTags":["<none>:<none>"],"Size":1},{"RepoTags":["tiny:1"],"Size":5}]`))
	})
	mux.HandleFunc("POST /containers/create", func(w http.ResponseWriter, r *http.Request) {
		note(r)
		var b struct {
			Image      string
			HostConfig struct{ Binds []string }
		}
		json.NewDecoder(r.Body).Decode(&b)
		e.mu.Lock()
		e.binds = append(e.binds, b.Image+"|"+strings.Join(b.HostConfig.Binds, ","))
		e.mu.Unlock()
		w.WriteHeader(201)
		w.Write([]byte(`{"Id":"helper1"}`))
	})
	mux.HandleFunc("GET /containers/{id}/archive", func(w http.ResponseWriter, r *http.Request) {
		note(r)
		data, ok := e.archive[r.URL.Query().Get("path")]
		if !ok {
			w.WriteHeader(404)
			w.Write([]byte(`{"message":"Could not find the file"}`))
			return
		}
		w.Write(data)
	})
	mux.HandleFunc("DELETE /containers/{id}", func(w http.ResponseWriter, r *http.Request) {
		note(r)
		e.mu.Lock()
		e.removed = append(e.removed, r.PathValue("id"))
		e.mu.Unlock()
		w.WriteHeader(204)
	})
	mux.HandleFunc("DELETE /images/{ref...}", func(w http.ResponseWriter, r *http.Request) {
		note(r)
		if strings.Contains(r.PathValue("ref"), "busy") {
			w.WriteHeader(409)
			w.Write([]byte(`{"message":"conflict: unable to delete busy:1 (cannot be forced) - image is being used by running container"}`))
			return
		}
		w.Write([]byte(`[{"Untagged":"x"}]`))
	})
	mux.HandleFunc("DELETE /networks/{n}", func(w http.ResponseWriter, r *http.Request) { note(r); w.WriteHeader(204) })
	mux.HandleFunc("DELETE /volumes/{v}", func(w http.ResponseWriter, r *http.Request) {
		note(r)
		if r.PathValue("v") == "inuse" {
			w.WriteHeader(409)
			w.Write([]byte(`{"message":"remove inuse: volume is in use - [abc]"}`))
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /networks/{n}", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Name":"proxy","Driver":"bridge","Scope":"local","Internal":false,"Containers":{"b":{"Name":"gitea","IPv4Address":"172.20.0.3/16"},"a":{"Name":"traefik","IPv4Address":"172.20.0.2/16"}}}`))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	e.d = New(sock)
	return e
}

func TestTakesArgAndTimeouts(t *testing.T) {
	d := newObjectsEngine(t).d
	for _, v := range []string{"rm-image", "rm-network", "rm-volume", "pull", "network-inspect", "volume-ls", "volume-read"} {
		if !d.TakesArg(v) {
			t.Errorf("%s takes an argument", v)
		}
	}
	for _, v := range []string{"start", "logs", "inspect", "stats", "inventory", "prune", "follow"} {
		if d.TakesArg(v) {
			t.Errorf("%s takes none", v)
		}
	}
	if d.Timeout("pull") < time.Minute || d.Timeout("rm-image") != 0 {
		t.Error("only a pull is given more time")
	}
}

func TestRemoveWithoutForceAndTheEnginesRefusalIsTheAnswer(t *testing.T) {
	e := newObjectsEngine(t)
	ctx := context.Background()
	if out, err := e.d.RunArg(ctx, "rm-image", "images", "old:1"); err != nil || !strings.Contains(out, "removed image old:1") {
		t.Errorf("%q %v", out, err)
	}
	if _, err := e.d.RunArg(ctx, "rm-image", "images", "busy:1"); err == nil || !strings.Contains(err.Error(), "being used") {
		t.Errorf("a used image must be refused with the engine's words: %v", err)
	}
	if _, err := e.d.RunArg(ctx, "rm-volume", "images", "inuse"); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Errorf("a volume in use: %v", err)
	}
	if _, err := e.d.RunArg(ctx, "rm-network", "images", "bridge"); err == nil {
		t.Error("a built-in network is never removed")
	}
	if _, err := e.d.RunArg(ctx, "rm-network", "images", "media"); err != nil {
		t.Error(err)
	}
	for _, c := range e.calls {
		if strings.Contains(c, "force") {
			t.Errorf("nothing is forced: %s", c)
		}
	}
}

func TestNetworkInspectListsWhoIsOnIt(t *testing.T) {
	e := newObjectsEngine(t)
	out, err := e.d.RunArg(context.Background(), "network-inspect", "images", "proxy")
	if err != nil {
		t.Fatal(err)
	}
	var n NetworkNow
	if err := json.Unmarshal([]byte(out), &n); err != nil {
		t.Fatal(err)
	}
	if n.Name != "proxy" || len(n.Containers) != 2 || n.Containers[0].Name != "gitea" || n.Containers[1].IPv4 != "172.20.0.2" {
		t.Errorf("%+v", n)
	}
}

func TestListingKeepsOnlyTheDirectChildren(t *testing.T) {
	e := newObjectsEngine(t)
	e.archive["/v"] = tarOf(map[string]string{"v/b.txt": "bb", "v/a.txt": "a", "v/sub/deep.txt": "deep", "v/sub/more/x": "x"}, "v/", "v/sub/", "v/sub/more/")
	out, err := e.d.RunArg(context.Background(), "volume-ls", "volume:pgdata", "")
	if err != nil {
		t.Fatal(err)
	}
	var l Listing
	json.Unmarshal([]byte(out), &l)
	names := []string{}
	for _, x := range l.Entries {
		names = append(names, x.Name)
	}
	if strings.Join(names, ",") != "sub,a.txt,b.txt" { // directories first
		t.Errorf("%v", names)
	}
	if !l.Entries[0].Dir || l.Entries[1].Size != 1 || l.Path != "/" {
		t.Errorf("%+v", l)
	}
	// the helper: the smallest named image, the volume mounted read only, then removed
	if len(e.binds) != 1 || e.binds[0] != "tiny:1|pgdata:/v:ro" {
		t.Errorf("binds %v", e.binds)
	}
	if len(e.removed) != 1 || e.removed[0] != "helper1" {
		t.Errorf("the helper container must go: %v", e.removed)
	}
}

func TestListingOfASubdirectory(t *testing.T) {
	e := newObjectsEngine(t)
	e.archive["/v/sub"] = tarOf(map[string]string{"sub/deep.txt": "deep"}, "sub/")
	out, err := e.d.RunArg(context.Background(), "volume-ls", "volume:pgdata", "/sub")
	if err != nil {
		t.Fatal(err)
	}
	var l Listing
	json.Unmarshal([]byte(out), &l)
	if l.Path != "/sub" || len(l.Entries) != 1 || l.Entries[0].Name != "deep.txt" {
		t.Errorf("%+v", l)
	}
	if _, err := e.d.RunArg(context.Background(), "volume-ls", "volume:pgdata", "/missing"); err == nil || !strings.Contains(err.Error(), "no such path") {
		t.Errorf("%v", err)
	}
}

func readFile(t *testing.T, e *objectsEngine, vol, p string) FileText {
	out, err := e.d.RunArg(context.Background(), "volume-read", "volume:"+vol, p)
	if err != nil {
		t.Fatal(err)
	}
	var f FileText
	json.Unmarshal([]byte(out), &f)
	return f
}

func TestReadingAFile(t *testing.T) {
	e := newObjectsEngine(t)
	e.archive["/v/hello.txt"] = tarOf(map[string]string{"hello.txt": "héllo\nworld\n"})
	if f := readFile(t, e, "v1", "/hello.txt"); f.Text != "héllo\nworld\n" || f.Size != 13 || f.Binary || f.Masked || f.Truncated {
		t.Errorf("%+v", f)
	}
	e.archive["/v/blob.bin"] = tarOf(map[string]string{"blob.bin": "ab\x00cd\xff"})
	if f := readFile(t, e, "v1", "/blob.bin"); !f.Binary || f.Text != "" {
		t.Errorf("a binary file shows no text: %+v", f)
	}
	big := strings.Repeat("x", readMax+500)
	e.archive["/v/big.log"] = tarOf(map[string]string{"big.log": big})
	if f := readFile(t, e, "v1", "/big.log"); !f.Truncated || len(f.Text) != readMax || f.Size != int64(len(big)) {
		t.Errorf("big file: truncated=%v len=%d size=%d", f.Truncated, len(f.Text), f.Size)
	}
	cut := strings.Repeat("é", readMax) // 2 bytes each: the limit cuts one in two
	e.archive["/v/utf.txt"] = tarOf(map[string]string{"utf.txt": cut})
	if f := readFile(t, e, "v1", "/utf.txt"); f.Binary || !f.Truncated {
		t.Errorf("a cut character at the limit is not a binary file: %+v", f)
	}
}

func TestSecretsAreNotShown(t *testing.T) {
	e := newObjectsEngine(t)
	e.archive["/v/.env"] = tarOf(map[string]string{".env": "# note\nDB_PASSWORD=hunter2\nTZ=UTC\n"})
	f := readFile(t, e, "v1", "/.env")
	if !f.Masked || strings.Contains(f.Text, "hunter2") || !strings.Contains(f.Text, "DB_PASSWORD=••••") || !strings.Contains(f.Text, "# note") {
		t.Errorf("a dotenv file shows names only: %+v", f)
	}
	for _, name := range []string{"server.pem", "id_rsa", "api_key.txt", "my-secret.json", "token", "passwords.csv", "id_ed25519"} {
		e.archive["/v/"+name] = tarOf(map[string]string{name: "TOP SECRET CONTENT"})
		f := readFile(t, e, "v1", "/"+name)
		if !f.Masked || f.Text != "" || f.Size == 0 {
			t.Errorf("%s: %+v", name, f)
		}
	}
	e.archive["/v/readme.md"] = tarOf(map[string]string{"readme.md": "plain"})
	if f := readFile(t, e, "v1", "/readme.md"); f.Masked || f.Text != "plain" {
		t.Errorf("%+v", f)
	}
}

func TestReadingADirectoryOrASymlinkIsRefused(t *testing.T) {
	e := newObjectsEngine(t)
	e.archive["/v/sub"] = tarOf(map[string]string{"sub/x": "x"}, "sub/")
	if _, err := e.d.RunArg(context.Background(), "volume-read", "volume:v1", "/sub"); err == nil {
		t.Error("a directory is not read as a file")
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	tw.Close()
	e.archive["/v/link"] = buf.Bytes()
	if _, err := e.d.RunArg(context.Background(), "volume-read", "volume:v1", "/link"); err == nil {
		t.Error("a symlink is not followed")
	}
}

func TestTheHelperIsRemovedEvenWhenTheReadFails(t *testing.T) {
	e := newObjectsEngine(t)
	e.d.RunArg(context.Background(), "volume-read", "volume:v1", "/nothing")
	if len(e.removed) != 1 {
		t.Errorf("removed %v", e.removed)
	}
}

func TestInventoryNamesWhoUsesWhat(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /system/df", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Images":[{"Id":"sha256:aaaaaaaaaaaaaaaa","RepoTags":["nginx:1"],"Size":100,"Containers":2},
		   {"Id":"sha256:bbbbbbbbbbbbbbbb","RepoTags":["<none>:<none>"],"Size":5,"Containers":0}],
		   "Volumes":[{"Name":"pgdata","Driver":"local","UsageData":{"Size":10,"RefCount":1}},{"Name":"unused","Driver":"local","UsageData":{"Size":1,"RefCount":0}}]}`))
	})
	mux.HandleFunc("GET /networks", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"Name":"proxy","Driver":"bridge","Scope":"local"},{"Name":"bridge","Driver":"bridge","Scope":"local"}]`))
	})
	mux.HandleFunc("GET /containers/json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"Names":["/web2"],"ImageID":"sha256:aaaaaaaaaaaaaaaa","Mounts":[],"NetworkSettings":{"Networks":{"proxy":{}}}},
		   {"Names":["/web1"],"ImageID":"sha256:aaaaaaaaaaaaaaaa","Mounts":[{"Name":"pgdata"},{"Name":""}],"NetworkSettings":{"Networks":{"proxy":{},"bridge":{}}}}]`))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	out, err := New(sock).inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var inv Inventory
	if err := json.Unmarshal([]byte(out), &inv); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(inv.Images[0].UsedBy, ","); got != "web1,web2" || len(inv.Images[1].UsedBy) != 0 {
		t.Errorf("images: %+v", inv.Images)
	}
	if got := strings.Join(inv.Volumes[0].UsedBy, ","); inv.Volumes[0].Name != "pgdata" || got != "web1" || len(inv.Volumes[1].UsedBy) != 0 {
		t.Errorf("volumes: %+v", inv.Volumes)
	}
	var proxy NetworkInfo
	for _, n := range inv.Networks {
		if n.Name == "proxy" {
			proxy = n
		}
	}
	if strings.Join(proxy.UsedBy, ",") != "web1,web2" || proxy.Used != 2 {
		t.Errorf("networks: %+v", inv.Networks)
	}
}
