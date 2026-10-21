// Package docker talks to the Docker Engine API on its unix socket, without the SDK: the list of
// containers with their state, health and whether their registry has a newer image; start, stop,
// restart, update (pull and recreate, update.go), the last lines of their logs (logs.go), their
// usage (stats.go), their crashes (events.go) and cleaning unused images (prune).
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/allow"
	"github.com/Mithrandler/labhud-agent/internal/caps"
	"github.com/Mithrandler/labhud-agent/internal/proto"
)

const Socket = "/var/run/docker.sock"

type Docker struct {
	c      *http.Client
	socket string            // for what an http.Client cannot do: a connection taken over (terminal.go)
	Allow  *allow.List       // the ticked containers: only their images are checked
	Send   func(proto.Event) // the end of an update, a crash: for labhud's timeline
	// AutoLabels: set on a container made again while labhud updates it on its own, removed when
	// it does not (config.AutoLabels)
	AutoLabels map[string]string
	// Scan gives the critical CVEs of an image id (the scan capability; nil without one): an
	// update with hold_critical compares the new image with the old one before it replaces it
	Scan func(ctx context.Context, imageID string) (int, error)

	mu      sync.Mutex
	updates map[string]bool  // container -> its registry has a newer image (CheckUpdates)
	busy    map[string]bool  // containers being updated
	crash   crashes          // events.go
	usage   map[string]usage // the ticked containers that run (stats.go)
}

// New gives nil when there is no socket.
func New(socket string) *Docker {
	if fi, err := os.Stat(socket); err != nil || fi.Mode()&os.ModeSocket == 0 {
		return nil
	}
	return &Docker{socket: socket, c: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}}
}

func (d *Docker) Name() string { return "docker" }

func (d *Docker) call(ctx context.Context, method, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	r, err := d.c.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if r.StatusCode == http.StatusNotModified { // already in that state
		return nil
	}
	if r.StatusCode >= 300 {
		var e struct{ Message string }
		if json.Unmarshal(body, &e) == nil && e.Message != "" {
			return fmt.Errorf("docker: %s", e.Message)
		}
		return fmt.Errorf("docker: HTTP %d", r.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

// health reads "(healthy)", "(unhealthy)", "(health: starting)" from the status line.
func health(status string) string {
	switch {
	case strings.Contains(status, "(healthy)"):
		return "healthy"
	case strings.Contains(status, "(unhealthy)"):
		return "unhealthy"
	case strings.Contains(status, "(health: starting)"):
		return "starting"
	}
	return ""
}

// own: the labhud.* labels (a card for the container: labhud.name, labhud.url, labhud.page…), at
// most 16, each at most 200 bytes; no other label leaves the host this way.
func own(labels map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range labels {
		if strings.HasPrefix(k, "labhud.") && len(k) <= 64 && len(out) < 16 {
			if len(v) > 200 {
				v = v[:200]
			}
			out[k] = v
		}
	}
	return out
}

func (d *Docker) Fill(ctx context.Context, st *proto.State) {
	var list []struct {
		Names  []string
		Image  string
		State  string
		Status string
		Labels map[string]string
	}
	if err := d.call(ctx, "GET", "/containers/json?all=1", &list); err != nil {
		return // no part: labhud keeps the last one and shows it stale
	}
	st.Containers = map[string]map[string]any{}
	for _, c := range list {
		if len(c.Names) == 0 {
			continue
		}
		e := map[string]any{"state": c.State, "image": c.Image, "status": c.Status}
		if h := health(c.Status); h != "" {
			e["health"] = h
		}
		if p := c.Labels["com.docker.compose.project"]; p != "" {
			e["project"] = p
		}
		if l := own(c.Labels); len(l) > 0 {
			e["labels"] = l
		}
		name := strings.TrimPrefix(c.Names[0], "/")
		d.mu.Lock()
		if u, ok := d.usage[name]; ok && c.State == "running" {
			u.put(e)
		}
		if d.updates[name] {
			e["update"] = true
		}
		if d.busy[name] {
			e["updating"] = true
		}
		d.mu.Unlock()
		st.Containers[name] = e
	}
}

func (d *Docker) Do(ctx context.Context, verb, target string) error {
	if verb == "update" {
		return d.UpdateWith(target, caps.UpdateOptions{})
	}
	if d.Reads(verb) || verb == "follow" {
		return fmt.Errorf("docker: %s is read, not done", verb)
	}
	path := "/containers/" + url.PathEscape(target) + "/" + verb
	if verb == "stop" || verb == "restart" {
		path += "?t=20"
	}
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	return d.call(ctx, "POST", path, nil)
}
