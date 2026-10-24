package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// A container's settings, edited from labhud: environment, published ports, bind mounts and the
// restart policy. `config` reads them (the environment as names only: a value is where a password
// lives, so a value is only ever written); `reconfigure` (the change sealed, as a stack's files
// are) makes the container again with them, or, for the restart policy alone, changes it live.
// A container that compose made is refused: its file would undo the change.

// ConfigView is what `config` tells.
type ConfigView struct {
	Managed     string   `json:"managed,omitempty"` // the compose project that made it: not editable here
	Self        bool     `json:"self,omitempty"`    // the agent's own container
	Restart     string   `json:"restart"`
	Ports       []string `json:"ports"`   // "[ip:]host:container[/proto]"
	Volumes     []string `json:"volumes"` // "source:target[:options]"
	OtherMounts int      `json:"other_mounts,omitempty"`
	Env         []string `json:"env"` // names only
}

// Change is what `reconfigure` takes; what is nil stays as it is.
type Change struct {
	EnvSet   map[string]string `json:"env_set,omitempty"`
	EnvUnset []string          `json:"env_unset,omitempty"`
	Ports    *[]string         `json:"ports,omitempty"`
	Volumes  *[]string         `json:"volumes,omitempty"`
	Restart  *string           `json:"restart,omitempty"`
}

const (
	maxEnv     = 150
	maxEnvVal  = 4096
	maxMapping = 60
)

var (
	envName    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)
	portSpec   = regexp.MustCompile(`^(?:([0-9]{1,3}(?:\.[0-9]{1,3}){3}):)?([0-9]{0,5}):([0-9]{1,5})(?:/(tcp|udp))?$`)
	volSpec    = regexp.MustCompile(`^(/[^:\x00-\x1f]*|[A-Za-z0-9][A-Za-z0-9_.-]{0,127}):(/[^:\x00-\x1f]*)(?::((?:ro|rw|z|Z|nocopy|shared|rshared|slave|rslave|private|rprivate)(?:,(?:ro|rw|z|Z|nocopy|shared|rshared|slave|rslave|private|rprivate))*))?$`)
	restartPol = regexp.MustCompile(`^(no|always|unless-stopped|on-failure(?::([0-9]{1,3}))?)$`)
)

func (d *Docker) configView(ctx context.Context, target string) (string, error) {
	var c map[string]any
	if err := d.send(ctx, "GET", "/containers/"+url.PathEscape(target)+"/json", nil, &c); err != nil {
		return "", err
	}
	id, _ := c["Id"].(string)
	v := ConfigView{Ports: []string{}, Volumes: []string{}, Env: []string{}, Self: d.self(id)}
	v.Managed, _ = dig(c, "Config", "Labels", "com.docker.compose.project").(string)
	v.Restart = restartText(c)
	if pb, ok := dig(c, "HostConfig", "PortBindings").(map[string]any); ok {
		for cport, binds := range pb {
			list, _ := binds.([]any)
			for _, b := range list {
				m, _ := b.(map[string]any)
				host, _ := m["HostPort"].(string)
				ip, _ := m["HostIp"].(string)
				s := host + ":" + cport
				if ip != "" && ip != "0.0.0.0" {
					s = ip + ":" + s
				}
				if !slices.Contains(v.Ports, s) {
					v.Ports = append(v.Ports, s)
				}
			}
		}
	}
	if binds, ok := dig(c, "HostConfig", "Binds").([]any); ok {
		for _, b := range binds {
			if s, _ := b.(string); s != "" {
				v.Volumes = append(v.Volumes, s)
			}
		}
	}
	if mounts, ok := c["Mounts"].([]any); ok {
		if n := len(mounts) - len(v.Volumes); n > 0 {
			v.OtherMounts = n // anonymous volumes and --mount ones: left as they are
		}
	}
	if env, ok := dig(c, "Config", "Env").([]any); ok {
		for _, e := range env {
			if s, _ := e.(string); s != "" {
				name, _, _ := strings.Cut(s, "=")
				v.Env = append(v.Env, name)
			}
		}
	}
	slices.Sort(v.Ports)
	slices.Sort(v.Env)
	out, err := json.Marshal(v)
	return string(out), err
}

func restartText(c map[string]any) string {
	name, _ := dig(c, "HostConfig", "RestartPolicy", "Name").(string)
	if name == "" {
		return "no"
	}
	if n, _ := dig(c, "HostConfig", "RestartPolicy", "MaximumRetryCount").(float64); name == "on-failure" && n > 0 {
		return "on-failure:" + strconv.Itoa(int(n))
	}
	return name
}

// Deploy carries out `reconfigure`: files["config"] is a Change.
func (d *Docker) Deploy(ctx context.Context, verb, target string, files map[string]string) (string, error) {
	if verb != "reconfigure" {
		return "", fmt.Errorf("docker: no verb %q takes files", verb)
	}
	var ch Change
	if err := json.Unmarshal([]byte(files["config"]), &ch); err != nil {
		return "", errors.New("the change does not read")
	}
	if err := ch.check(); err != nil {
		return "", err
	}
	var old map[string]any
	if err := d.send(ctx, "GET", "/containers/"+url.PathEscape(target)+"/json", nil, &old); err != nil {
		return "", err
	}
	id, _ := old["Id"].(string)
	name := strings.TrimPrefix(fmt.Sprint(old["Name"]), "/")
	if name != target {
		return "", errors.New("the container is not the one named")
	}
	if d.self(id) {
		return "", errors.New("this is the agent's own container: change it from its host")
	}
	if p, _ := dig(old, "Config", "Labels", "com.docker.compose.project").(string); p != "" {
		return "", fmt.Errorf("%s was made by compose (%s): change its file instead", name, p)
	}
	d.mu.Lock()
	if d.busy == nil {
		d.busy = map[string]bool{}
	}
	if d.busy[name] {
		d.mu.Unlock()
		return "", errors.New("an update or a change of it is already running")
	}
	d.busy[name] = true
	d.mu.Unlock()
	defer func() { d.mu.Lock(); delete(d.busy, name); d.mu.Unlock() }()

	if ch.onlyRestart() {
		return d.setRestart(ctx, id, name, *ch.Restart)
	}
	ref, _ := dig(old, "Config", "Image").(string)
	oldImage, _ := old["Image"].(string)
	if ref == "" || strings.HasPrefix(ref, "sha256:") {
		return "", errors.New("the container runs an image id, not a name: nothing to make it from")
	}
	var img struct{ Id string }
	if err := d.send(ctx, "GET", "/images/"+url.PathEscape(ref)+"/json", nil, &img); err != nil || img.Id != oldImage {
		return "", errors.New("the image name now points to another image than the one running: update the container first")
	}
	create, extra := spec(old, ref, nil)
	ch.apply(create)
	d.autoLabels(create, name)
	if _, err := d.swap(ctx, name, old, create, extra); err != nil {
		return "", fmt.Errorf("%w (the old one runs again, as it was)", err)
	}
	msg := name + " made again with the new settings"
	if err := d.dropOld(ctx, id); err != nil {
		msg += " (the old container stays as " + name + keepSuffix + ")"
	}
	return msg, nil
}

func (d *Docker) setRestart(ctx context.Context, id, name, policy string) (string, error) {
	p := restartPol.FindStringSubmatch(policy)
	rp := map[string]any{"Name": strings.SplitN(policy, ":", 2)[0], "MaximumRetryCount": 0}
	if p[2] != "" {
		rp["MaximumRetryCount"], _ = strconv.Atoi(p[2])
	}
	body := map[string]any{"RestartPolicy": rp}
	if err := d.send(ctx, "POST", "/containers/"+url.PathEscape(id)+"/update", body, nil); err != nil {
		return "", err
	}
	return name + ": restart policy is now " + policy, nil
}

func (c Change) onlyRestart() bool {
	return c.Restart != nil && len(c.EnvSet) == 0 && len(c.EnvUnset) == 0 && c.Ports == nil && c.Volumes == nil
}

// check refuses what is not the shape of a setting, before any API is touched.
func (c Change) check() error {
	if len(c.EnvSet) == 0 && len(c.EnvUnset) == 0 && c.Ports == nil && c.Volumes == nil && c.Restart == nil {
		return errors.New("nothing to change")
	}
	if len(c.EnvSet)+len(c.EnvUnset) > maxEnv {
		return errors.New("too many variables")
	}
	for k, v := range c.EnvSet {
		if !envName.MatchString(k) {
			return fmt.Errorf("%q is not a variable name", k)
		}
		if len(v) > maxEnvVal || strings.ContainsRune(v, 0) {
			return fmt.Errorf("the value of %s is too long or has a NUL", k)
		}
	}
	for _, k := range c.EnvUnset {
		if !envName.MatchString(k) {
			return fmt.Errorf("%q is not a variable name", k)
		}
		if _, both := c.EnvSet[k]; both {
			return fmt.Errorf("%s is both set and removed", k)
		}
	}
	if c.Ports != nil {
		if len(*c.Ports) > maxMapping {
			return errors.New("too many ports")
		}
		seen := map[string]bool{}
		for _, p := range *c.Ports {
			m := portSpec.FindStringSubmatch(p)
			if m == nil {
				return fmt.Errorf("%q is not a port mapping ([ip:]host:container[/tcp|udp])", p)
			}
			if n, _ := strconv.Atoi(m[3]); n < 1 || n > 65535 {
				return fmt.Errorf("%q: container port out of range", p)
			}
			if m[2] != "" {
				if n, _ := strconv.Atoi(m[2]); n < 1 || n > 65535 {
					return fmt.Errorf("%q: host port out of range", p)
				}
			}
			for _, o := range strings.Split(m[1], ".") {
				if n, _ := strconv.Atoi(o); n > 255 {
					return fmt.Errorf("%q: not an address", p)
				}
			}
			if seen[p] {
				return fmt.Errorf("%q twice", p)
			}
			seen[p] = true
		}
	}
	if c.Volumes != nil {
		if len(*c.Volumes) > maxMapping {
			return errors.New("too many volumes")
		}
		seen := map[string]bool{}
		for _, v := range *c.Volumes {
			m := volSpec.FindStringSubmatch(v)
			if m == nil || slices.Contains(strings.Split(m[2], "/"), "..") || slices.Contains(strings.Split(m[1], "/"), "..") {
				return fmt.Errorf("%q is not a volume (source:target[:ro])", v)
			}
			if seen[m[2]] {
				return fmt.Errorf("two volumes at %s", m[2])
			}
			seen[m[2]] = true
		}
	}
	if c.Restart != nil && !restartPol.MatchString(*c.Restart) {
		return fmt.Errorf("%q is not a restart policy (no, always, unless-stopped, on-failure[:N])", *c.Restart)
	}
	return nil
}

// apply puts the change into the body of POST /containers/create (made by spec).
func (c Change) apply(create map[string]any) {
	if len(c.EnvSet) > 0 || len(c.EnvUnset) > 0 {
		var out []any
		set := map[string]bool{}
		old, _ := create["Env"].([]any)
		for _, e := range old {
			s, _ := e.(string)
			name, _, _ := strings.Cut(s, "=")
			if slices.Contains(c.EnvUnset, name) {
				continue
			}
			if v, ok := c.EnvSet[name]; ok {
				out = append(out, name+"="+v)
				set[name] = true
				continue
			}
			out = append(out, e)
		}
		names := make([]string, 0, len(c.EnvSet))
		for k := range c.EnvSet {
			if !set[k] {
				names = append(names, k)
			}
		}
		slices.Sort(names)
		for _, k := range names {
			out = append(out, k+"="+c.EnvSet[k])
		}
		create["Env"] = out
	}
	host := map[string]any{}
	if h, ok := create["HostConfig"].(map[string]any); ok {
		for k, v := range h {
			host[k] = v
		}
	}
	create["HostConfig"] = host
	if c.Ports != nil {
		bindings := map[string]any{}
		exposed := map[string]any{}
		for _, p := range *c.Ports {
			m := portSpec.FindStringSubmatch(p)
			proto := m[4]
			if proto == "" {
				proto = "tcp"
			}
			key := m[3] + "/" + proto
			exposed[key] = map[string]any{}
			list, _ := bindings[key].([]any)
			bindings[key] = append(list, map[string]any{"HostIp": m[1], "HostPort": m[2]})
		}
		host["PortBindings"] = bindings
		if old, ok := create["ExposedPorts"].(map[string]any); ok {
			for k, v := range old {
				if _, in := exposed[k]; !in {
					exposed[k] = v // a port the image declares stays declared
				}
			}
		}
		create["ExposedPorts"] = exposed
	}
	if c.Volumes != nil {
		binds := make([]any, 0, len(*c.Volumes))
		for _, v := range *c.Volumes {
			binds = append(binds, v)
		}
		host["Binds"] = binds
	}
	if c.Restart != nil {
		p := restartPol.FindStringSubmatch(*c.Restart)
		rp := map[string]any{"Name": strings.SplitN(*c.Restart, ":", 2)[0]}
		if p[2] != "" {
			n, _ := strconv.Atoi(p[2])
			rp["MaximumRetryCount"] = n
		}
		host["RestartPolicy"] = rp
	}
}
