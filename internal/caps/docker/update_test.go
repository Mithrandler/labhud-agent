package docker

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/allow"
	"github.com/Mithrandler/labhud-agent/internal/proto"
)

// engine is a fake Docker Engine with one container "web" on image "old", whose tag
// "nginx:1" now points at image "new".
type engine struct {
	mu        sync.Mutex
	calls     []string
	created   map[string]any
	connected []string
	newRuns   bool     // the new container stays up
	health    []string // the new container's health status at each look (the last stays); none: no HEALTHCHECK
	healthOut string   // the output of its last health probe
	pullErr   string   // an error line in the pull stream
	auth      []string // the X-Registry-Auth of each pull ("" without one)
	names     map[string]string
}

func (e *engine) log(r *http.Request) {
	e.mu.Lock()
	e.calls = append(e.calls, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
	e.mu.Unlock()
}

func (e *engine) start(t *testing.T) *Docker {
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	e.names = map[string]string{"web": "oldid0000000000"}
	old := map[string]any{
		"Id": "oldid0000000000", "Image": "sha256:old", "Name": "/web",
		"State": map[string]any{"Running": true},
		"Config": map[string]any{"Image": "nginx:1", "Hostname": "oldid0000000", "Tty": false,
			"Env":    []any{"PATH=/usr/bin", "MINE=1"},
			"Cmd":    []any{"nginx", "-g", "daemon off;"},
			"Labels": map[string]any{"maintainer": "nginx", "com.docker.compose.service": "web"}},
		"HostConfig": map[string]any{"NetworkMode": "front", "Binds": []any{"/srv:/srv"}},
		"NetworkSettings": map[string]any{"Networks": map[string]any{
			"front": map[string]any{"Aliases": []any{"web", "oldid0000000"}, "IPAddress": "172.18.0.2", "NetworkID": "n1"},
			"back":  map[string]any{"Aliases": []any{"web"}, "IPAddress": "172.19.0.2"}}},
	}
	images := map[string]map[string]any{
		"sha256:old": {"Id": "sha256:old", "RepoDigests": []any{"nginx@sha256:aaa"},
			"Config": map[string]any{"Env": []any{"PATH=/usr/bin"}, "Cmd": []any{"nginx", "-g", "daemon off;"},
				"Labels": map[string]any{"maintainer": "nginx"}}},
		"nginx:1": {"Id": "sha256:new", "RepoDigests": []any{"nginx@sha256:bbb"},
			"Config": map[string]any{"Labels": map[string]any{"org.opencontainers.image.version": "1.2"}}},
	}
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, v any) { json.NewEncoder(w).Encode(v) }
	mux.HandleFunc("GET /containers/json", func(w http.ResponseWriter, r *http.Request) {
		j(w, []map[string]any{{"Names": []string{"/web"}}, {"Names": []string{}}})
	})
	mux.HandleFunc("GET /containers/{name}/json", func(w http.ResponseWriter, r *http.Request) {
		switch n := r.PathValue("name"); {
		case n == "web" || n == "oldid0000000000":
			j(w, old)
		case n == "newid":
			st := map[string]any{"Running": e.newRuns, "ExitCode": 1}
			e.mu.Lock()
			if len(e.health) > 0 {
				st["Health"] = map[string]any{"Status": e.health[0], "Log": []any{map[string]any{"Output": e.healthOut}}}
				if len(e.health) > 1 {
					e.health = e.health[1:]
				}
			}
			e.mu.Unlock()
			j(w, map[string]any{"State": st})
		default:
			w.WriteHeader(404)
			j(w, map[string]any{"message": "No such container: " + n})
		}
	})
	mux.HandleFunc("GET /containers/{name}/logs", func(w http.ResponseWriter, r *http.Request) {
		e.log(r)
		frame := func(stream byte, s string) {
			h := make([]byte, 8)
			h[0] = stream
			binary.BigEndian.PutUint32(h[4:], uint32(len(s)))
			w.Write(append(h, s...))
		}
		frame(1, "\x1b[32mstarted\x1b[0m\r\n")
		frame(2, "warning: x\n")
	})
	mux.HandleFunc("GET /images/{ref...}", func(w http.ResponseWriter, r *http.Request) {
		ref := strings.TrimSuffix(r.PathValue("ref"), "/json")
		if img, ok := images[ref]; ok {
			j(w, img)
			return
		}
		w.WriteHeader(404)
	})
	mux.HandleFunc("GET /distribution/{ref...}", func(w http.ResponseWriter, r *http.Request) {
		j(w, map[string]any{"Descriptor": map[string]any{"Digest": "sha256:bbb"}})
	})
	mux.HandleFunc("POST /images/create", func(w http.ResponseWriter, r *http.Request) {
		e.log(r)
		e.mu.Lock()
		e.auth = append(e.auth, r.Header.Get("X-Registry-Auth"))
		e.mu.Unlock()
		fmt.Fprintln(w, `{"status":"Pulling from library/nginx"}`)
		if e.pullErr != "" {
			fmt.Fprintf(w, `{"error":%q}`+"\n", e.pullErr)
		}
	})
	mux.HandleFunc("POST /containers/create", func(w http.ResponseWriter, r *http.Request) {
		e.log(r)
		json.NewDecoder(r.Body).Decode(&e.created)
		j(w, map[string]any{"Id": "newid"})
	})
	mux.HandleFunc("POST /networks/{net}/connect", func(w http.ResponseWriter, r *http.Request) {
		e.log(r)
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		e.mu.Lock()
		e.connected = append(e.connected, r.PathValue("net")+":"+fmt.Sprint(b["Container"]))
		e.mu.Unlock()
	})
	mux.HandleFunc("POST /containers/{name}/{verb}", func(w http.ResponseWriter, r *http.Request) {
		e.log(r)
		w.WriteHeader(204)
	})
	mux.HandleFunc("DELETE /containers/{name}", func(w http.ResponseWriter, r *http.Request) {
		e.log(r)
		w.WriteHeader(204)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return New(sock)
}

func (e *engine) seen() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return strings.Join(e.calls, "\n")
}

func TestLogs(t *testing.T) {
	d := (&engine{}).start(t)
	out, err := d.Read(t.Context(), "logs", "web")
	if err != nil || out != "started\nwarning: x\n" {
		t.Fatalf("%q %v", out, err)
	}
	if _, err := d.Read(t.Context(), "logs", "missing"); err == nil || !strings.Contains(err.Error(), "No such container") {
		t.Errorf("got %v", err)
	}
	if !d.Reads("logs") || d.Reads("restart") {
		t.Error("only logs is read")
	}
}

func TestDemuxKeepsAPlainStream(t *testing.T) {
	if got := string(demux([]byte("plain text, a TTY\n"))); got != "plain text, a TTY\n" {
		t.Errorf("%q", got)
	}
}

func TestCheckUpdates(t *testing.T) {
	d := (&engine{}).start(t)
	d.Allow = &allow.List{}
	d.CheckUpdates(t.Context()) // nothing ticked: still read, so labhud can show the update
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.updates["web"] {
		t.Error("the registry's sha256:bbb is not the image's sha256:aaa: an update, ticked or not")
	}
}

func TestSpec(t *testing.T) {
	e := &engine{}
	e.start(t)
	old := map[string]any{
		"Id": "abcdef1234567890", "Config": map[string]any{"Hostname": "abcdef123456", "Image": "x:1",
			"Env": []any{"A=1", "B=2"}, "Labels": map[string]any{"img": "1", "own": "2", "changed": "3"},
			"Cmd": []any{"run"}, "User": "app"},
		"HostConfig":      map[string]any{"NetworkMode": "host"},
		"NetworkSettings": map[string]any{"Networks": map[string]any{"host": map[string]any{}}},
	}
	img := map[string]any{"Env": []any{"A=1"}, "Labels": map[string]any{"img": "1", "changed": "0"}, "Cmd": []any{"run"}}
	body, extra := spec(old, "x:2", img)
	if _, ok := body["Hostname"]; ok || body["Image"] != "x:2" {
		t.Errorf("hostname kept or image not changed: %v", body)
	}
	if fmt.Sprint(body["Env"]) != "[B=2]" || fmt.Sprint(body["Labels"]) != "map[changed:3 own:2]" {
		t.Errorf("env %v labels %v", body["Env"], body["Labels"])
	}
	if _, ok := body["Cmd"]; ok || body["User"] != "app" {
		t.Errorf("the image's command stays the image's, the own user stays: %v", body)
	}
	if _, ok := body["NetworkingConfig"]; ok || extra != nil {
		t.Errorf("host network: no endpoints, got %v %v", body["NetworkingConfig"], extra)
	}
}

func TestUpdate(t *testing.T) {
	saved := StartWait
	StartWait = 10 * time.Millisecond
	t.Cleanup(func() { StartWait = saved })
	for _, tc := range []struct {
		name    string
		runs    bool
		pullErr string
		want    string
		bad     bool
	}{
		{"ok", true, "", "web updated (old → 1.2)", false},
		{"does not stay up", false, "", "web: update failed: the new container does not stay up (exit code 1) (the old one runs again; this version is skipped until a newer one is out)", true},
		{"pull fails", true, "toomanyrequests", "web: update failed: pull nginx:1: toomanyrequests", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &engine{newRuns: tc.runs, pullErr: tc.pullErr}
			d := e.start(t)
			got := make(chan proto.Event, 1)
			d.Send = func(ev proto.Event) { got <- ev }
			if err := d.Do(t.Context(), "update", "web"); err != nil {
				t.Fatal(err)
			}
			var ev proto.Event
			select {
			case ev = <-got:
			case <-time.After(5 * time.Second):
				t.Fatal("no event")
			}
			if ev.Text != tc.want || ev.Bad != tc.bad || ev.Kind != "update" || ev.Target != "web" {
				t.Fatalf("event %+v, calls:\n%s", ev, e.seen())
			}
			if !tc.bad && (ev.From != "old" || ev.To != "1.2") {
				t.Errorf("from %q to %q", ev.From, ev.To)
			}
			calls := e.seen()
			switch tc.name {
			case "ok":
				for _, want := range []string{"POST /containers/oldid0000000000/stop?t=20", "rename?name=web-labhud-old",
					"POST /containers/create?name=web", "POST /networks/back/connect?", "POST /containers/newid/start?",
					"DELETE /containers/oldid0000000000?"} {
					if !strings.Contains(calls, want) {
						t.Errorf("no %q in:\n%s", want, calls)
					}
				}
				nc := fmt.Sprint(e.created["NetworkingConfig"])
				if !strings.Contains(nc, "front") || strings.Contains(nc, "IPAddress") || strings.Contains(nc, "oldid") {
					t.Errorf("the first network, without runtime fields and the old id alias: %s", nc)
				}
				if fmt.Sprint(e.created["Env"]) != "[MINE=1]" || e.created["Hostname"] != nil {
					t.Errorf("created %v", e.created)
				}
			case "does not stay up":
				for _, want := range []string{"DELETE /containers/newid?force=1", "POST /containers/oldid0000000000/rename?name=web",
					"POST /containers/oldid0000000000/start?"} {
					if !strings.Contains(calls, want) {
						t.Errorf("no %q in:\n%s", want, calls)
					}
				}
			case "pull fails":
				if strings.Contains(calls, "/stop") {
					t.Errorf("stopped before the pull worked:\n%s", calls)
				}
			}
		})
	}
}

func TestUpdateRefusals(t *testing.T) {
	d := (&engine{}).start(t)
	if err := d.Do(t.Context(), "update", "missing"); err == nil {
		t.Error("a missing container")
	}
	d.busy = map[string]bool{"web": true}
	if err := d.Do(t.Context(), "update", "web"); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Errorf("got %v", err)
	}
	for _, ref := range []string{"sha256:abc", "nginx@sha256:abc", "Bad/Name"} {
		if pullable(ref) {
			t.Errorf("%s is not pulled by tag", ref)
		}
	}
	for _, ref := range []string{"nginx", "ghcr.io/x/y:1.2", "registry:5000/a/b:latest"} {
		if !pullable(ref) {
			t.Errorf("%s is", ref)
		}
	}
	if r, tag := split("registry:5000/a/b"); r != "registry:5000/a/b" || tag != "latest" {
		t.Errorf("%s %s", r, tag)
	}
}

func TestUpdateWaitsForHealth(t *testing.T) {
	savedWait, savedPoll := HealthWait, HealthPoll
	HealthWait, HealthPoll = 100*time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { HealthWait, HealthPoll = savedWait, savedPoll })
	for _, tc := range []struct {
		name   string
		health []string
		want   string // the start of the event's text
		bad    bool
	}{
		{"turns healthy", []string{"starting", "starting", "healthy"}, "web updated (old → 1.2)", false},
		{"unhealthy", []string{"starting", "unhealthy"}, "web: update failed: the new container is unhealthy (curl: connection refused) (the old one runs again", true},
		{"never healthy", []string{"starting"}, "web: update failed: the new container is not healthy after 0.1s (the old one runs again", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &engine{newRuns: true, health: tc.health, healthOut: "curl: connection refused\n"}
			d := e.start(t)
			got := make(chan proto.Event, 1)
			d.Send = func(ev proto.Event) { got <- ev }
			if err := d.Do(t.Context(), "update", "web"); err != nil {
				t.Fatal(err)
			}
			var ev proto.Event
			select {
			case ev = <-got:
			case <-time.After(5 * time.Second):
				t.Fatal("no event")
			}
			if !strings.HasPrefix(ev.Text, tc.want) || ev.Bad != tc.bad || ev.Kind != "update" {
				t.Fatalf("event %+v, calls:\n%s", ev, e.seen())
			}
			calls := e.seen()
			if tc.bad != strings.Contains(calls, "DELETE /containers/newid?force=1") {
				t.Errorf("the new container goes exactly when the update is undone:\n%s", calls)
			}
			// an undone version is not offered again by the check (so an automatic update leaves it)
			d.Allow = &allow.List{}
			d.CheckUpdates(t.Context())
			d.mu.Lock()
			offered := d.updates["web"]
			d.mu.Unlock()
			// it worked: the engine's fake still says the old image runs, so it is offered; undone: it is not
			if offered == tc.bad {
				t.Errorf("offered %v after an update that went bad=%v", offered, tc.bad)
			}
		})
	}
}

func TestHealthWindow(t *testing.T) {
	label := func(v string) map[string]any {
		return map[string]any{"Config": map[string]any{"Labels": map[string]any{healthWaitLabel: v}}}
	}
	for v, want := range map[string]time.Duration{"30": 30 * time.Second, " 600 ": 600 * time.Second, "4": HealthWait,
		"601": HealthWait, "soon": HealthWait, "": HealthWait} {
		if got := healthWindow(label(v)); got != want {
			t.Errorf("label %q: %v, want %v", v, got, want)
		}
	}
	if healthWindow(map[string]any{}) != HealthWait {
		t.Error("no label: the default")
	}
}
