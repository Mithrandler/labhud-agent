// Package stacks keeps docker compose projects on this host, for the admin to deploy from labhud:
// a folder per stack under one directory (LABHUD_AGENT_STACKS) holding compose.yaml and an
// optional .env, run with the host's `docker compose`. It is the one capability that runs a
// program, so it is off unless that directory is set, and what it runs is fixed: the program is
// found once at start, the arguments are built here (never from labhud's text), no shell is
// involved, and the files live only in <dir>/<name>/. A compose file can ask for anything the
// Docker socket can (privileged, a bind of /): ticking `stacks` is as strong as ticking the
// socket. `down` never removes volumes.
package stacks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/proto"
)

const (
	// MaxFile bounds one file of a stack.
	MaxFile = 48 << 10
	// Slow: a deploy or a redeploy pulls images
	Slow = 8 * time.Minute
	// Quick: the others
	Quick = 90 * time.Second
)

var name = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Stacks is the capability.
type Stacks struct {
	Dir string   // where the stacks live
	bin []string // the program and its first arguments: ["docker", "compose"] or ["docker-compose"]
	run func(ctx context.Context, dir string, args ...string) (string, error)
}

// New gives nil without a directory, or without `docker compose` (or docker-compose) to run.
func New(dir string, look func(string) (string, error)) *Stacks {
	if dir == "" {
		return nil
	}
	if look == nil {
		look = exec.LookPath
	}
	s := &Stacks{Dir: dir}
	if p, err := look("docker"); err == nil {
		if out, err := execute(context.Background(), "", append([]string{p}, "compose", "version")...); err == nil && strings.Contains(out, "ompose") {
			s.bin = []string{p, "compose"}
		}
	}
	if s.bin == nil {
		if p, err := look("docker-compose"); err == nil {
			s.bin = []string{p}
		}
	}
	if s.bin == nil || os.MkdirAll(dir, 0o700) != nil {
		return nil
	}
	s.run = func(ctx context.Context, wd string, args ...string) (string, error) {
		return execute(ctx, wd, append(append([]string{}, s.bin...), args...)...)
	}
	return s
}

func (s *Stacks) Name() string { return "stacks" }

// environment is all a compose run gets from the agent's own: where docker is, and nothing of
// the agent's settings.
func environment() []string {
	var out []string
	for _, k := range []string{"PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "XDG_RUNTIME_DIR"} {
		if v := os.Getenv(k); v != "" {
			out = append(out, k+"="+v)
		}
	}
	return out
}

func execute(ctx context.Context, wd string, argv ...string) (string, error) {
	// #nosec G204 -- argv[0] was found on PATH at start; the arguments are built in this package
	c := exec.CommandContext(ctx, argv[0], argv[1:]...)
	c.Dir = wd
	c.Env = environment()
	var buf bytes.Buffer
	c.Stdout, c.Stderr = &buf, &buf
	err := c.Run()
	return buf.String(), err
}

func (s *Stacks) Timeout(verb string) time.Duration {
	if verb == "deploy" || verb == "redeploy" {
		return Slow
	}
	return Quick
}

func (s *Stacks) dir(target string) (string, error) {
	if !name.MatchString(target) {
		return "", errors.New("stacks: a stack's name is lowercase letters, digits, - and _")
	}
	return filepath.Join(s.Dir, target), nil
}

// Fill: the stacks that have a folder here, with their files.
func (s *Stacks) Fill(ctx context.Context, st *proto.State) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return
	}
	st.Stacks = map[string]map[string]any{}
	for _, e := range entries {
		if !e.IsDir() || !name.MatchString(e.Name()) {
			continue
		}
		fi, err := os.Stat(filepath.Join(s.Dir, e.Name(), "compose.yaml"))
		if err != nil {
			continue
		}
		x := map[string]any{"updated": fi.ModTime().Unix()}
		if _, err := os.Stat(filepath.Join(s.Dir, e.Name(), ".env")); err == nil {
			x["env"] = true
		}
		st.Stacks[e.Name()] = x
	}
}

func (s *Stacks) Do(ctx context.Context, verb, target string) error {
	_, err := s.Read(ctx, verb, target)
	return err
}

func (s *Stacks) Reads(verb string) bool {
	switch verb {
	case "deploy", "redeploy", "restart", "down", "show":
		return true
	}
	return false
}

// args are the compose arguments of a stack, the project named after it.
func args(target string, env bool, more ...string) []string {
	a := []string{"-p", target, "-f", "compose.yaml"}
	if env {
		a = append(a, "--env-file", ".env")
	}
	return append(a, more...)
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// Read: show, and the verbs that need no files (redeploy, restart, down).
func (s *Stacks) Read(ctx context.Context, verb, target string) (string, error) {
	dir, err := s.dir(target)
	if err != nil {
		return "", err
	}
	if !exists(filepath.Join(dir, "compose.yaml")) {
		return "", errors.New("stacks: no such stack here")
	}
	env := exists(filepath.Join(dir, ".env"))
	switch verb {
	case "show":
		return show(dir)
	case "redeploy":
		out, err := s.run(ctx, dir, args(target, env, "pull")...)
		if err != nil {
			return out, fail("pull", out, err)
		}
		more, err := s.run(ctx, dir, args(target, env, "up", "-d", "--remove-orphans")...)
		return out + more, fail("up", more, err)
	case "restart":
		out, err := s.run(ctx, dir, args(target, env, "restart")...)
		return out, fail("restart", out, err)
	case "down": // never -v: the volumes are somebody's data
		out, err := s.run(ctx, dir, args(target, env, "down", "--remove-orphans")...)
		return out, fail("down", out, err)
	}
	return "", fmt.Errorf("stacks: no verb %q", verb)
}

// show gives the compose file as it is, and the .env's names: its values are where passwords live.
func show(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "compose.yaml"))
	if err != nil {
		return "", err
	}
	out := string(b)
	if e, err := os.ReadFile(filepath.Join(dir, ".env")); err == nil {
		var names []string
		for _, line := range strings.Split(string(e), "\n") {
			if k, _, ok := strings.Cut(strings.TrimSpace(line), "="); ok && !strings.HasPrefix(k, "#") && k != "" {
				names = append(names, strings.TrimSpace(k))
			}
		}
		sort.Strings(names)
		out += "\n# .env: " + strings.Join(names, ", ") + "\n"
	}
	return out, nil
}

// fail turns a compose error into a short message with the last line it printed.
func fail(step, out string, err error) error {
	if err == nil {
		return nil
	}
	last := ""
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(l) != "" {
			last = strings.TrimSpace(l)
		}
	}
	if len(last) > 150 {
		last = last[:150]
	}
	return fmt.Errorf("compose %s: %s", step, last)
}

// Deploy writes the files and brings the stack up. The compose file is checked first
// (`config --quiet`); a failing one leaves the old files as they were.
func (s *Stacks) Deploy(ctx context.Context, verb, target string, files map[string]string) (string, error) {
	if verb != "deploy" {
		return "", fmt.Errorf("stacks: %s takes no files", verb)
	}
	dir, err := s.dir(target)
	if err != nil {
		return "", err
	}
	compose := files["compose"]
	if strings.TrimSpace(compose) == "" || len(compose) > MaxFile || len(files["env"]) > MaxFile {
		return "", fmt.Errorf("stacks: a compose file, at most %d KiB (the .env too)", MaxFile>>10)
	}
	for k := range files {
		if k != "compose" && k != "env" {
			return "", fmt.Errorf("stacks: no file %q", k)
		}
	}
	// the new files go in a scratch folder first, to be checked there
	tmp, err := os.MkdirTemp(s.Dir, ".new-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	if err := os.WriteFile(filepath.Join(tmp, "compose.yaml"), []byte(compose), 0o600); err != nil {
		return "", err
	}
	// "env" missing keeps the .env the host has; "" takes it away
	envText, given := files["env"]
	if !given {
		if old, err := os.ReadFile(filepath.Join(dir, ".env")); err == nil {
			envText, given = string(old), true
		}
	}
	env := envText != ""
	if env {
		if err := os.WriteFile(filepath.Join(tmp, ".env"), []byte(envText), 0o600); err != nil {
			return "", err
		}
	}
	if out, err := s.run(ctx, tmp, args(target, env, "config", "--quiet")...); err != nil {
		return out, fail("config", out, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for _, f := range []string{"compose.yaml", ".env"} {
		src := filepath.Join(tmp, f)
		if !exists(src) {
			os.Remove(filepath.Join(dir, f)) // a .env taken away is taken away
			continue
		}
		if err := os.Rename(src, filepath.Join(dir, f)); err != nil {
			return "", err
		}
	}
	out, err := s.run(ctx, dir, args(target, env, "up", "-d", "--remove-orphans")...)
	return out, fail("up", out, err)
}
