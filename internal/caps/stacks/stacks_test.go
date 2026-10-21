package stacks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fake is a `docker` that writes the arguments it got to a log and fails `config` when the
// compose file says "broken".
func fake(t *testing.T) (*Stacks, string) {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(bin, "calls.log")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = compose ] && [ \"$2\" = version ]; then echo 'Docker Compose version v2.30'; exit 0; fi\n" +
		"echo \"$PWD: $*\" >> " + log + "\n" +
		"case \"$*\" in *config*) grep -q broken compose.yaml && { echo 'yaml: line 3: broken'; exit 1; };; esac\n" +
		"echo ok\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	s := New(filepath.Join(t.TempDir(), "stacks"), nil)
	if s == nil {
		t.Fatal("no stacks capability")
	}
	return s, log
}

func calls(t *testing.T, log string) []string {
	b, _ := os.ReadFile(log)
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func TestOffWithoutDirOrCompose(t *testing.T) {
	if New("", nil) != nil {
		t.Error("a capability without a folder")
	}
	t.Setenv("PATH", t.TempDir())
	if New(t.TempDir(), nil) != nil {
		t.Error("a capability without docker compose")
	}
}

func TestDeployWritesChecksAndRuns(t *testing.T) {
	s, log := fake(t)
	out, err := s.Deploy(context.Background(), "deploy", "web", map[string]string{"compose": "services: {}\n", "env": "TOKEN=abc\n"})
	if err != nil {
		t.Fatal(err, out)
	}
	dir := filepath.Join(s.Dir, "web")
	for f, want := range map[string]string{"compose.yaml": "services: {}\n", ".env": "TOKEN=abc\n"} {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil || string(b) != want {
			t.Errorf("%s: %q %v", f, b, err)
		}
		if fi, _ := os.Stat(filepath.Join(dir, f)); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s is %v", f, fi.Mode().Perm())
		}
	}
	c := calls(t, log)
	if len(c) != 2 { // `compose version` is answered before the log
		t.Fatalf("calls: %v", c)
	}
	last := c[len(c)-1]
	if !strings.HasSuffix(last, "compose -p web -f compose.yaml --env-file .env up -d --remove-orphans") || !strings.HasPrefix(last, dir+":") {
		t.Errorf("up: %q", last)
	}
	if !strings.Contains(c[0], "config --quiet") {
		t.Errorf("not checked first: %v", c)
	}
	if entries, _ := os.ReadDir(s.Dir); len(entries) != 1 {
		t.Errorf("scratch folder left: %v", entries)
	}
}

func TestBrokenComposeLeavesTheOldFiles(t *testing.T) {
	s, log := fake(t)
	if _, err := s.Deploy(context.Background(), "deploy", "web", map[string]string{"compose": "services: {}\n"}); err != nil {
		t.Fatal(err)
	}
	_, err := s.Deploy(context.Background(), "deploy", "web", map[string]string{"compose": "broken\n"})
	if err == nil || !strings.Contains(err.Error(), "broken") {
		t.Fatalf("err: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(s.Dir, "web", "compose.yaml"))
	if string(b) != "services: {}\n" {
		t.Errorf("the old file was replaced: %q", b)
	}
	if n := strings.Count(strings.Join(calls(t, log), "\n"), "up -d"); n != 1 {
		t.Errorf("up ran %d times: a broken stack was brought up", n)
	}
}

func TestEnvTakenAwayIsRemoved(t *testing.T) {
	s, _ := fake(t)
	ctx := context.Background()
	s.Deploy(ctx, "deploy", "web", map[string]string{"compose": "services: {}\n", "env": "A=1\n"})
	s.Deploy(ctx, "deploy", "web", map[string]string{"compose": "services: {}\n"})
	if _, err := os.Stat(filepath.Join(s.Dir, "web", ".env")); err == nil {
		t.Error(".env stayed")
	}
}

func TestRefusals(t *testing.T) {
	s, _ := fake(t)
	ctx := context.Background()
	for _, bad := range []string{"../etc", "Web", "a/b", "", "-x", strings.Repeat("a", 65)} {
		if _, err := s.Deploy(ctx, "deploy", bad, map[string]string{"compose": "x"}); err == nil {
			t.Errorf("deployed %q", bad)
		}
	}
	if _, err := s.Deploy(ctx, "deploy", "web", map[string]string{"compose": "x", "sh": "rm"}); err == nil {
		t.Error("another file name")
	}
	if _, err := s.Deploy(ctx, "deploy", "web", map[string]string{"compose": strings.Repeat("a", MaxFile+1)}); err == nil {
		t.Error("a file over the bound")
	}
	if _, err := s.Deploy(ctx, "down", "web", map[string]string{"compose": "x"}); err == nil {
		t.Error("down with files")
	}
	if _, err := s.Read(ctx, "down", "nothere"); err == nil {
		t.Error("down on a stack that is not here")
	}
}

func TestDownKeepsVolumesAndShowHidesValues(t *testing.T) {
	s, log := fake(t)
	ctx := context.Background()
	s.Deploy(ctx, "deploy", "web", map[string]string{"compose": "services: {}\n", "env": "# c\nTOKEN=secret\nB = 2\n"})
	if _, err := s.Read(ctx, "down", "web"); err != nil {
		t.Fatal(err)
	}
	c := calls(t, log)
	if last := c[len(c)-1]; strings.Contains(last, " -v") || !strings.HasSuffix(last, "down --remove-orphans") {
		t.Errorf("down: %q", last)
	}
	out, err := s.Read(ctx, "show", "web")
	if err != nil || strings.Contains(out, "secret") || !strings.Contains(out, "# .env: B, TOKEN") {
		t.Errorf("show: %q %v", out, err)
	}
}

func TestRedeployPullsThenUps(t *testing.T) {
	s, log := fake(t)
	ctx := context.Background()
	s.Deploy(ctx, "deploy", "web", map[string]string{"compose": "services: {}\n"})
	if _, err := s.Read(ctx, "redeploy", "web"); err != nil {
		t.Fatal(err)
	}
	c := calls(t, log)
	n := len(c)
	if !strings.HasSuffix(c[n-2], " pull") || !strings.HasSuffix(c[n-1], "up -d --remove-orphans") {
		t.Errorf("calls: %v", c[n-2:])
	}
}
