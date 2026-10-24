package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// TakesArg: the verbs that name an object (the image, network or volume) or a path; allow.CheckArg
// has already checked the argument's shape. All of them but the volume ones are the host's Docker
// (target "images", ticked on its own); the volume ones are for a volume ticked for browsing.
func (d *Docker) TakesArg(verb string) bool {
	switch verb {
	case "rm-image", "rm-network", "rm-volume", "pull", "network-inspect", "volume-ls", "volume-read":
		return true
	}
	return false
}

// Timeout: a pull may take minutes; everything else the usual.
func (d *Docker) Timeout(verb string) time.Duration {
	switch verb {
	case "pull":
		return 10 * time.Minute
	case "reconfigure": // the container made again, given its health window
		return HealthWait + StartWait + 90*time.Second
	}
	return 0
}

func (d *Docker) RunArg(ctx context.Context, verb, target, arg string) (string, error) {
	switch verb {
	case "rm-image":
		return d.remove(ctx, "/images/"+url.PathEscape(arg), "image "+arg)
	case "rm-network":
		if builtin(arg) {
			return "", fmt.Errorf("docker: %s is a built-in network", arg)
		}
		return d.remove(ctx, "/networks/"+url.PathEscape(arg), "network "+arg)
	case "rm-volume":
		return d.remove(ctx, "/volumes/"+url.PathEscape(arg), "volume "+arg)
	case "pull":
		if err := d.pull(ctx, arg, "", nil); err != nil {
			return "", err
		}
		return "pulled " + arg, nil
	case "network-inspect":
		return d.networkInspect(ctx, arg)
	case "volume-ls":
		return d.volumeLs(ctx, strings.TrimPrefix(target, "volume:"), arg)
	case "volume-read":
		return d.volumeRead(ctx, strings.TrimPrefix(target, "volume:"), arg)
	}
	return "", fmt.Errorf("docker: no verb %q", verb)
}

// remove deletes one object without force: the engine refuses what something still uses
// ("conflict: image is being used", "volume is in use"), which is the answer.
func (d *Docker) remove(ctx context.Context, path, what string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	if err := d.call(ctx, "DELETE", path, nil); err != nil {
		return "", err
	}
	return "removed " + what, nil
}

// NetworkNow is `network-inspect`'s answer: who is on a network.
type NetworkNow struct {
	Name       string        `json:"name"`
	Driver     string        `json:"driver"`
	Scope      string        `json:"scope"`
	Internal   bool          `json:"internal"`
	Containers []NetworkLink `json:"containers"`
}

type NetworkLink struct {
	Name string `json:"name"`
	IPv4 string `json:"ipv4,omitempty"`
}

func (d *Docker) networkInspect(ctx context.Context, name string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var n struct {
		Name, Driver, Scope string
		Internal            bool
		Containers          map[string]struct{ Name, IPv4Address string }
	}
	if err := d.call(ctx, "GET", "/networks/"+url.PathEscape(name), &n); err != nil {
		return "", err
	}
	out := NetworkNow{Name: n.Name, Driver: n.Driver, Scope: n.Scope, Internal: n.Internal, Containers: []NetworkLink{}}
	for _, c := range n.Containers {
		out.Containers = append(out.Containers, NetworkLink{Name: c.Name, IPv4: strings.SplitN(c.IPv4Address, "/", 2)[0]})
	}
	sort.Slice(out.Containers, func(a, b int) bool { return out.Containers[a].Name < out.Containers[b].Name })
	if len(out.Containers) > 100 {
		out.Containers = out.Containers[:100]
	}
	b, err := json.Marshal(out)
	return string(b), err
}
