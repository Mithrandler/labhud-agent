package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/caps"
	"github.com/Mithrandler/labhud-agent/internal/proto"
)

// How often the ticked containers' images are compared with their registry, and how long an
// update (pull + recreate) may take.
var (
	CheckEvery = 6 * time.Hour
	CheckFirst = 2 * time.Minute
	PullMax    = 10 * time.Minute
	StartWait  = 15 * time.Second
	// A container with a HEALTHCHECK is given HealthWait (or its label's seconds) to turn healthy
	// before its update is undone; HealthPoll is how often it is looked at.
	HealthWait = 120 * time.Second
	HealthPoll = 2 * time.Second
)

// healthWaitLabel on a container: the seconds its new version has to turn healthy (5 to 600).
const healthWaitLabel = "labhud.health-wait"

// healthWindow is how long the new container of an update is given: the old one's label, else HealthWait.
func healthWindow(old map[string]any) time.Duration {
	if v, _ := dig(old, "Config", "Labels", healthWaitLabel).(string); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 5 && n <= 600 {
			return time.Duration(n) * time.Second
		}
	}
	return HealthWait
}

// imageRef: a name to pull by tag ("nginx", "ghcr.io/x/y:1.2"), not an id or a pinned digest.
var imageRef = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*(:[0-9]+)?[a-z0-9._/-]*(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?$`)

func pullable(ref string) bool {
	return imageRef.MatchString(ref) && !strings.HasPrefix(ref, "sha256:") && !strings.Contains(ref, "@")
}

// split gives the repository and the tag of a reference ("latest" when it has none).
func split(ref string) (repo, tag string) {
	slash := strings.LastIndex(ref, "/")
	if i := strings.LastIndex(ref, ":"); i > slash {
		return ref[:i], ref[i+1:]
	}
	return ref, "latest"
}

func (d *Docker) send(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	r, err := d.c.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if r.StatusCode == http.StatusNotModified {
		return nil
	}
	if r.StatusCode >= 300 {
		var e struct{ Message string }
		if json.Unmarshal(b, &e) == nil && e.Message != "" {
			return fmt.Errorf("docker: %s", e.Message)
		}
		return fmt.Errorf("docker: HTTP %d", r.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// --- update available ---------------------------------------------------------------------

// Watch compares the ticked containers' images with their registry, after CheckFirst and then
// every CheckEvery, until ctx ends. Fill reports the result as "update": true.
func (d *Docker) Watch(ctx context.Context) {
	t := time.NewTimer(CheckFirst)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		d.CheckUpdates(ctx)
		t.Reset(CheckEvery)
	}
}

// CheckUpdates asks the registry (through the engine, with its own logins) for the digest of
// each container's tag, once per image, and compares it with the image's RepoDigests. Every
// container is checked (a read only, so labhud can show which ones have an update); only the
// ticked ones can be updated. An image built here or pinned by digest has no answer and is left out.
func (d *Docker) CheckUpdates(ctx context.Context) {
	var list []struct{ Names []string }
	if d.call(ctx, "GET", "/containers/json?all=1", &list) != nil {
		return // keep the last answer
	}
	found := map[string]bool{}
	type verdict struct {
		newer  *bool
		digest string
	}
	known := map[string]verdict{} // image reference -> newer in the registry
	for _, c := range list {
		if len(c.Names) == 0 {
			continue
		}
		name := strings.TrimPrefix(c.Names[0], "/")
		var c struct {
			Image  string
			Config struct{ Image string }
		}
		if d.send(ctx, "GET", "/containers/"+url.PathEscape(name)+"/json", nil, &c) != nil {
			continue
		}
		ref := c.Config.Image
		if _, done := known[ref]; !done {
			n, dg := d.newer(ctx, ref, c.Image)
			known[ref] = verdict{n, dg}
		}
		// a version that was undone (it did not turn healthy) is not offered again; the next one is
		if v := known[ref]; v.newer != nil && *v.newer && !d.isRejected(name, v.digest) {
			found[name] = true
		}
	}
	d.mu.Lock()
	d.updates = found
	d.mu.Unlock()
}

// newer: true when the registry's digest for `ref` is none of the image's, nil when not known; the
// digest is the registry's.
func (d *Docker) newer(ctx context.Context, ref, imageID string) (*bool, string) {
	if !pullable(ref) {
		return nil, ""
	}
	var img struct{ RepoDigests []string }
	if d.send(ctx, "GET", "/images/"+imageID+"/json", nil, &img) != nil || len(img.RepoDigests) == 0 {
		return nil, ""
	}
	var dist struct{ Descriptor struct{ Digest string } }
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if d.send(cctx, "GET", "/distribution/"+ref+"/json", nil, &dist) != nil || dist.Descriptor.Digest == "" {
		return nil, ""
	}
	have := false
	for _, rd := range img.RepoDigests {
		if _, dg, ok := strings.Cut(rd, "@"); ok && dg == dist.Descriptor.Digest {
			have = true
		}
	}
	v := !have
	return &v, dist.Descriptor.Digest
}

// --- update: pull, then the container again with the new image ----------------------------

// ImageOf gives the image id a container runs (for the scan capability).
func (d *Docker) ImageOf(ctx context.Context, name string) (string, error) {
	var c struct{ Image string }
	if err := d.send(ctx, "GET", "/containers/"+url.PathEscape(name)+"/json", nil, &c); err != nil {
		return "", err
	}
	return c.Image, nil
}

// held: an update kept back because the new image has more critical CVEs (hold_critical).
type held struct{ text string }

func (h held) Error() string { return h.text }

// UpdateWith checks what can be checked at once and runs the rest in the background: the answer
// to labhud is "started", the end is an event ("jellyfin updated", or why not). A registry login
// is used only when the image comes from that very registry (the engine would hand it to the
// image's registry, whichever it is), only for this pull, and is never logged or written.
func (d *Docker) UpdateWith(name string, opt caps.UpdateOptions) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var raw map[string]any
	if err := d.send(ctx, "GET", "/containers/"+url.PathEscape(name)+"/json", nil, &raw); err != nil {
		return err
	}
	ref, _ := dig(raw, "Config", "Image").(string)
	if !pullable(ref) {
		return fmt.Errorf("%s runs %q: not an image name with a tag, nothing to pull", name, ref)
	}
	id, _ := raw["Id"].(string)
	if d.self(id) {
		return errors.New("this is the agent's own container: update it from its host")
	}
	d.mu.Lock()
	if d.busy == nil {
		d.busy = map[string]bool{}
	}
	if d.busy[name] {
		d.mu.Unlock()
		return errors.New("an update of it is already running")
	}
	d.busy[name] = true
	d.mu.Unlock()
	if opt.Login != nil && proto.RegistryOf(ref) != opt.Registry {
		opt.Login = nil // a login for another registry than the image's: not this one's to see
	}
	go func() {
		defer func() { d.mu.Lock(); delete(d.busy, name); d.mu.Unlock() }()
		uctx, cancel := context.WithTimeout(context.Background(), PullMax)
		defer cancel()
		ev, err := d.recreate(uctx, name, ref, raw, opt)
		var h held
		if errors.As(err, &h) {
			d.send1(proto.Event{Text: h.text, Bad: true, Cap: "docker", Target: name, Kind: "held"})
			return
		}
		if err != nil {
			d.send1(proto.Event{Text: fmt.Sprintf("%s: update failed: %v", name, err), Bad: true,
				Cap: "docker", Target: name, Kind: "update"})
			return
		}
		d.mu.Lock()
		delete(d.updates, name)
		d.mu.Unlock()
		d.send1(ev)
	}()
	return nil
}

func (d *Docker) send1(ev proto.Event) {
	if d.Send != nil {
		d.Send(ev)
	}
}

// version names an image for the update history: its org.opencontainers.image.version label,
// else its short id.
func version(config map[string]any, id string) string {
	if v, _ := dig(config, "Labels", "org.opencontainers.image.version").(string); v != "" {
		if len(v) > 40 {
			v = v[:40]
		}
		return v
	}
	return short(id)
}

// self: the container this agent runs in (Docker sets the hostname to the short id).
func (d *Docker) self(id string) bool {
	h, err := os.Hostname()
	return err == nil && len(h) >= 12 && strings.HasPrefix(id, h)
}

func dig(m map[string]any, keys ...string) any {
	var v any = m
	for _, k := range keys {
		mm, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = mm[k]
	}
	return v
}

// registryAuth is the X-Registry-Auth header for a login: URL-safe base64 of its JSON.
func registryAuth(registry string, l *proto.Login) string {
	server := registry
	if registry == proto.DockerHub {
		server = "https://index.docker.io/v1/"
	}
	b, _ := json.Marshal(map[string]string{"username": l.Username, "password": l.Password, "serveraddress": server})
	return base64.URLEncoding.EncodeToString(b)
}

// pull reads the engine's progress stream to its end; an "error" line is the failure. With a
// login (already checked to be for the image's registry), the engine gets it for this pull only.
func (d *Docker) pull(ctx context.Context, ref string, registry string, login *proto.Login) error {
	repo, tag := split(ref)
	req, err := http.NewRequestWithContext(ctx, "POST", "http://docker/images/create?fromImage="+url.QueryEscape(repo)+"&tag="+url.QueryEscape(tag), nil)
	if err != nil {
		return err
	}
	if login != nil {
		req.Header.Set("X-Registry-Auth", registryAuth(registry, login))
	}
	r, err := d.c.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode >= 300 {
		var e struct{ Message string }
		json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&e)
		if e.Message == "" {
			e.Message = fmt.Sprintf("HTTP %d", r.StatusCode)
		}
		return fmt.Errorf("pull %s: %s", ref, e.Message)
	}
	sc := bufio.NewScanner(r.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var line struct{ Error string }
		if json.Unmarshal(sc.Bytes(), &line) == nil && line.Error != "" {
			return fmt.Errorf("pull %s: %s", ref, line.Error)
		}
	}
	return sc.Err()
}

// recreate: pull; if the image changed, stop the old container, keep it under another name,
// make the new one from the old one's settings, start it; the old one goes only once the new
// one runs. Anything failing after the stop puts the old one back as it was.
func (d *Docker) recreate(ctx context.Context, name, ref string, old map[string]any, opt caps.UpdateOptions) (proto.Event, error) {
	var none proto.Event
	oldID, _ := old["Id"].(string)
	oldImage, _ := old["Image"].(string)
	// read before the pull: the pull takes the tag from this image, and the containerd image store
	// forgets an image with no name (the settings it gave would be kept as the container's own)
	var oldImg struct{ Config map[string]any }
	d.send(ctx, "GET", "/images/"+oldImage+"/json", nil, &oldImg) // gone: nothing to leave out
	if err := d.pull(ctx, ref, opt.Registry, opt.Login); err != nil {
		return none, err
	}
	var img struct {
		Id          string
		Config      map[string]any
		RepoDigests []string
	}
	if err := d.send(ctx, "GET", "/images/"+ref+"/json", nil, &img); err != nil {
		return none, err
	}
	if img.Id == oldImage {
		return proto.Event{Text: name + " is already on the newest image"}, nil
	}
	if err := d.hold(ctx, name, img.Id, oldImage, opt); err != nil {
		return none, err
	}
	create, extra := spec(old, ref, oldImg.Config)
	d.autoLabels(create, name)
	if stage, err := d.swap(ctx, name, old, create, extra); err != nil {
		if stage == "start" {
			d.reject(name, img.RepoDigests)
			return none, fmt.Errorf("%w (the old one runs again; this version is skipped until a newer one is out)", err)
		}
		return none, err
	}
	from, to := version(oldImg.Config, oldImage), version(img.Config, img.Id)
	d.reject(name, nil)
	ev := proto.Event{Cap: "docker", Target: name, Kind: "update", From: from, To: to,
		Text: fmt.Sprintf("%s updated (%s → %s)", name, from, to)}
	if err := d.dropOld(ctx, oldID); err != nil {
		ev.Text = fmt.Sprintf("%s updated (the old container stays as %s: %v)", name, name+keepSuffix, err)
	}
	return ev, nil
}

const keepSuffix = "-labhud-old"

// swap puts a new container made from `create` in the place of `old`: the old one is stopped
// and kept under another name, the new one is made, joined to its other networks and started
// (and must stay up, or turn healthy). Anything failing puts the old one back as it was; the
// stage ("stop", "create" or "start") tells where it failed. On success the old one still
// exists: dropOld removes it.
func (d *Docker) swap(ctx context.Context, name string, old, create map[string]any, extra []network) (string, error) {
	oldID, _ := old["Id"].(string)
	wasRunning, _ := dig(old, "State", "Running").(bool)
	keep := name + keepSuffix
	if err := d.send(ctx, "POST", "/containers/"+url.PathEscape(oldID)+"/stop?t=20", nil, nil); err != nil {
		return "stop", fmt.Errorf("stop: %w", err)
	}
	if err := d.send(ctx, "POST", "/containers/"+url.PathEscape(oldID)+"/rename?name="+url.QueryEscape(keep), nil, nil); err != nil {
		d.restore(oldID, name, wasRunning, "")
		return "stop", fmt.Errorf("rename: %w", err)
	}
	var made struct{ Id string }
	if err := d.send(ctx, "POST", "/containers/create?name="+url.QueryEscape(name), create, &made); err != nil {
		d.restore(oldID, name, wasRunning, "")
		return "create", fmt.Errorf("create: %w (the old one runs again)", err)
	}
	for _, net := range extra {
		if err := d.send(ctx, "POST", "/networks/"+url.PathEscape(net.name)+"/connect",
			map[string]any{"Container": made.Id, "EndpointConfig": net.config}, nil); err != nil {
			d.restore(oldID, name, wasRunning, made.Id)
			return "create", fmt.Errorf("network %s: %w (the old one runs again)", net.name, err)
		}
	}
	if wasRunning {
		if err := d.started(ctx, made.Id, healthWindow(old)); err != nil {
			d.restore(oldID, name, wasRunning, made.Id)
			return "start", err
		}
	}
	return "", nil
}

func (d *Docker) dropOld(ctx context.Context, oldID string) error {
	return d.send(ctx, "DELETE", "/containers/"+url.PathEscape(oldID), nil, nil)
}

// autoLabels puts AutoLabels on a container labhud updates on its own and takes them off one it
// does not (any more), so that another updater knows which ones are labhud's.
func (d *Docker) autoLabels(create map[string]any, name string) {
	if len(d.AutoLabels) == 0 {
		return
	}
	labels, _ := create["Labels"].(map[string]any)
	if labels == nil {
		labels = map[string]any{}
	}
	auto := d.Allow != nil && d.Allow.Auto("docker", name)
	for k, v := range d.AutoLabels {
		if auto {
			labels[k] = v
		} else if labels[k] == v {
			delete(labels, k)
		}
	}
	create["Labels"] = labels
}

func short(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// started: the new container starts and stays up. With a HEALTHCHECK it is given `wait` to turn
// healthy (unhealthy, or still starting at the end, is a failure); without one it must still be
// running (not restarting) StartWait later.
func (d *Docker) started(ctx context.Context, id string, wait time.Duration) error {
	path := "/containers/" + url.PathEscape(id)
	if err := d.send(ctx, "POST", path+"/start", nil, nil); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	var st struct {
		State struct {
			Running, Restarting bool
			ExitCode            int
			Health              *struct {
				Status string
				Log    []struct{ Output string }
			}
		}
	}
	look := func() error { return d.send(ctx, "GET", path+"/json", nil, &st) }
	pause := func(t time.Duration) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(t):
			return nil
		}
	}
	if err := look(); err != nil {
		return err
	}
	if st.State.Health == nil || st.State.Health.Status == "none" {
		if err := pause(StartWait); err != nil {
			return err
		}
		if err := look(); err != nil {
			return err
		}
		if !st.State.Running || st.State.Restarting {
			return fmt.Errorf("the new container does not stay up (exit code %d)", st.State.ExitCode)
		}
		return nil
	}
	deadline := time.Now().Add(wait)
	for {
		if !st.State.Running || st.State.Restarting {
			return fmt.Errorf("the new container does not stay up (exit code %d)", st.State.ExitCode)
		}
		switch h := st.State.Health; {
		case h == nil, h.Status == "healthy":
			return nil
		case h.Status == "unhealthy":
			out := ""
			if n := len(h.Log); n > 0 {
				out = strings.TrimSpace(h.Log[n-1].Output)
				if len(out) > 120 {
					out = out[:120]
				}
			}
			if out != "" {
				return fmt.Errorf("the new container is unhealthy (%s)", out)
			}
			return errors.New("the new container is unhealthy")
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("the new container is not healthy after %gs", wait.Seconds())
		}
		if err := pause(HealthPoll); err != nil {
			return err
		}
		if err := look(); err != nil {
			return err
		}
	}
}

// reject remembers the registry digests of an image that was undone for `name` (none: forget them,
// an update worked). CheckUpdates does not offer that very version again, so an automatic update
// does not try it over and over; a newer one has another digest, and the button still tries it.
func (d *Docker) reject(name string, digests []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(digests) == 0 {
		delete(d.rejected, name)
		return
	}
	if d.rejected == nil {
		d.rejected = map[string][]string{}
	}
	var only []string
	for _, rd := range digests {
		if _, dg, ok := strings.Cut(rd, "@"); ok {
			only = append(only, dg)
		}
	}
	d.rejected[name] = only
}

func (d *Docker) isRejected(name, digest string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, dg := range d.rejected[name] {
		if dg == digest {
			return true
		}
	}
	return false
}

// restore: the new container (if any) goes, the old one gets its name back and runs again.
func (d *Docker) restore(oldID, name string, wasRunning bool, newID string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if newID != "" {
		d.send(ctx, "DELETE", "/containers/"+url.PathEscape(newID)+"?force=1", nil, nil)
	}
	d.send(ctx, "POST", "/containers/"+url.PathEscape(oldID)+"/rename?name="+url.QueryEscape(name), nil, nil)
	if wasRunning {
		d.send(ctx, "POST", "/containers/"+url.PathEscape(oldID)+"/start", nil, nil)
	}
}

type network struct {
	name   string
	config map[string]any
}

// The parts of an endpoint the engine works out itself (and refuses or ignores when given).
var endpointRuntime = []string{"NetworkID", "EndpointID", "Gateway", "IPAddress", "IPPrefixLen", "IPv6Gateway",
	"GlobalIPv6Address", "GlobalIPv6PrefixLen", "MacAddress", "DNSNames"}

// spec is the body of POST /containers/create for the same container on `ref`: the old one's
// Config without what came from its old image (so the new image's own env, command, labels
// apply), its HostConfig as it is, and its first network; `extra` are the others, connected
// after the create.
func spec(old map[string]any, ref string, oldImage map[string]any) (map[string]any, []network) {
	cfg := map[string]any{}
	if c, ok := old["Config"].(map[string]any); ok {
		for k, v := range c {
			cfg[k] = v
		}
	}
	id, _ := old["Id"].(string)
	if h, _ := cfg["Hostname"].(string); h != "" && strings.HasPrefix(id, h) {
		delete(cfg, "Hostname") // the old id, set by Docker: the new one gets its own
	}
	cfg["Image"] = ref
	if oldImage != nil {
		cfg["Env"] = without(cfg["Env"], oldImage["Env"])
		for _, k := range []string{"Labels", "Volumes", "ExposedPorts"} {
			cfg[k] = withoutKeys(cfg[k], oldImage[k], k == "Labels")
		}
		for _, k := range []string{"Cmd", "Entrypoint", "WorkingDir", "User", "Healthcheck", "StopSignal", "Shell", "OnBuild"} {
			if v, ok := cfg[k]; ok && reflect.DeepEqual(v, oldImage[k]) {
				delete(cfg, k)
			}
		}
	}
	body := map[string]any{}
	for k, v := range cfg {
		body[k] = v
	}
	host, _ := old["HostConfig"].(map[string]any)
	body["HostConfig"] = host
	mode, _ := dig(old, "HostConfig", "NetworkMode").(string)
	nets, _ := dig(old, "NetworkSettings", "Networks").(map[string]any)
	if mode == "host" || mode == "none" || strings.HasPrefix(mode, "container:") || len(nets) == 0 {
		return body, nil
	}
	names := make([]string, 0, len(nets))
	for n := range nets {
		names = append(names, n)
	}
	sort.Strings(names)
	if i := slices.Index(names, mode); i > 0 { // the one in NetworkMode first
		names[0], names[i] = names[i], names[0]
	}
	var all []network
	for _, n := range names {
		ep := map[string]any{}
		if e, ok := nets[n].(map[string]any); ok {
			for k, v := range e {
				if !slices.Contains(endpointRuntime, k) && v != nil {
					ep[k] = v
				}
			}
		}
		if al, ok := ep["Aliases"].([]any); ok { // the old short id is not an alias to keep
			kept := []any{}
			for _, a := range al {
				if s, _ := a.(string); s == "" || !strings.HasPrefix(id, s) {
					kept = append(kept, a)
				}
			}
			ep["Aliases"] = kept
		}
		all = append(all, network{n, ep})
	}
	body["NetworkingConfig"] = map[string]any{"EndpointsConfig": map[string]any{all[0].name: all[0].config}}
	return body, all[1:]
}

// without: the entries of list `a` that are not in `b` (an env line from the image).
func without(a, b any) any {
	la, ok := a.([]any)
	lb, _ := b.([]any)
	if !ok || len(lb) == 0 {
		return a
	}
	out := []any{}
	for _, x := range la {
		if !slices.Contains(lb, x) {
			out = append(out, x)
		}
	}
	return out
}

// withoutKeys: the keys of map `a` that are not in `b` (or, for labels, that `b` has with
// another value: a label the container set itself).
func withoutKeys(a, b any, sameValue bool) any {
	ma, ok := a.(map[string]any)
	mb, _ := b.(map[string]any)
	if !ok || len(mb) == 0 {
		return a
	}
	out := map[string]any{}
	for k, v := range ma {
		if bv, in := mb[k]; !in || (sameValue && !reflect.DeepEqual(bv, v)) {
			out[k] = v
		}
	}
	return out
}

// hold: with hold_critical, the new image is scanned before anything is stopped, and kept out
// when it has more critical CVEs than the one running. A new image that cannot be scanned is
// kept out too (the option is a promise); one the old image cannot be compared with counts
// against none.
func (d *Docker) hold(ctx context.Context, name, newImage, oldImage string, opt caps.UpdateOptions) error {
	if !opt.HoldCritical || d.Scan == nil {
		return nil
	}
	now, err := d.Scan(ctx, newImage)
	if err != nil {
		return held{fmt.Sprintf("%s: update held: the new image could not be scanned (%v)", name, err)}
	}
	before, err := d.Scan(ctx, oldImage)
	if err != nil {
		before = 0
	}
	if now > before {
		return held{fmt.Sprintf("%s: update held: %d critical CVEs in the new image (%d now)", name, now, before)}
	}
	return nil
}
