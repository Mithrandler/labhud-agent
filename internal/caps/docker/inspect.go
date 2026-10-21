package docker

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

// Details is what `inspect` tells about a container: how it is made, never a secret. The
// environment gives names only (values are where passwords live), and so do the labels of the
// form *password*, *token*, *secret*, *key* (their values are left out).
type Details struct {
	Image    string            `json:"image"`
	Created  string            `json:"created"`
	Started  string            `json:"started,omitempty"`
	Restart  string            `json:"restart"`
	Restarts int               `json:"restarts"`
	Ports    []string          `json:"ports"`
	Mounts   []string          `json:"mounts"`
	Networks []string          `json:"networks"`
	Env      []string          `json:"env"`
	Labels   map[string]string `json:"labels"`
	Health   string            `json:"health,omitempty"`
	Command  string            `json:"command,omitempty"`
}

var secretWords = []string{"pass", "token", "secret", "key", "auth", "credential", "cookie"}

func secretish(name string) bool {
	n := strings.ToLower(name)
	for _, w := range secretWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

type inspected struct {
	Created      string
	RestartCount int
	State        struct {
		StartedAt string
		Health    *struct{ Status string }
	}
	Config struct {
		Image  string
		Env    []string
		Labels map[string]string
		Cmd    []string
	}
	HostConfig struct {
		RestartPolicy struct {
			Name              string
			MaximumRetryCount int
		}
	}
	NetworkSettings struct {
		Ports    map[string][]struct{ HostIp, HostPort string }
		Networks map[string]any
	}
	Mounts []struct {
		Type, Name, Source, Destination string
		RW                              bool
	}
}

// details keeps the shape, drops the secrets.
func details(c inspected) Details {
	d := Details{Image: c.Config.Image, Created: c.Created, Started: c.State.StartedAt,
		Restart: c.HostConfig.RestartPolicy.Name, Restarts: c.RestartCount,
		Ports: []string{}, Mounts: []string{}, Networks: []string{}, Env: []string{}, Labels: map[string]string{}}
	if d.Restart == "" {
		d.Restart = "no"
	}
	if c.State.Health != nil {
		d.Health = c.State.Health.Status
	}
	for port, binds := range c.NetworkSettings.Ports {
		if len(binds) == 0 {
			d.Ports = append(d.Ports, port)
		}
		seen := map[string]bool{}
		for _, b := range binds {
			p := b.HostPort + "→" + port
			if !seen[p] { // the same port on 0.0.0.0 and ::
				seen[p] = true
				d.Ports = append(d.Ports, p)
			}
		}
	}
	for _, m := range c.Mounts {
		src := m.Source
		if m.Type == "volume" {
			src = m.Name
		}
		mode := "ro"
		if m.RW {
			mode = "rw"
		}
		d.Mounts = append(d.Mounts, src+" → "+m.Destination+" ("+mode+")")
	}
	for n := range c.NetworkSettings.Networks {
		d.Networks = append(d.Networks, n)
	}
	for _, e := range c.Config.Env {
		name, _, _ := strings.Cut(e, "=")
		d.Env = append(d.Env, name)
	}
	for k, v := range c.Config.Labels {
		if secretish(k) {
			v = "…"
		}
		if len(v) > 200 {
			v = v[:200] + "…"
		}
		d.Labels[k] = v
	}
	if len(c.Config.Cmd) > 0 && !secretish(strings.Join(c.Config.Cmd, " ")) {
		d.Command = strings.Join(c.Config.Cmd, " ")
		if len(d.Command) > 200 {
			d.Command = d.Command[:200] + "…"
		}
	}
	for _, l := range [][]string{d.Ports, d.Mounts, d.Networks, d.Env} {
		sort.Strings(l)
	}
	return d
}

func (d *Docker) inspect(ctx context.Context, target string) (string, error) {
	var c inspected
	if err := d.call(ctx, "GET", "/containers/"+url.PathEscape(target)+"/json", &c); err != nil {
		return "", err
	}
	b, err := json.Marshal(details(c))
	return string(b), err
}
