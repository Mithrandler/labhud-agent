package systemd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sd "github.com/coreos/go-systemd/v22/dbus"

	"github.com/Mithrandler/labhud-agent/internal/allow"
	"github.com/Mithrandler/labhud-agent/internal/proto"
)

type fakeBus struct {
	mu       sync.Mutex
	calls    []string
	result   string
	props    []sd.Property
	patterns []string
	release  chan struct{} // holds the transient job until closed
}

func (b *fakeBus) ListUnitsByPatternsContext(_ context.Context, states, patterns []string) ([]sd.UnitStatus, error) {
	if len(states) > 0 {
		return []sd.UnitStatus{{Name: "nginx.service", ActiveState: "failed"}, {Name: "a.mount", ActiveState: "failed"}}, nil
	}
	b.patterns = patterns
	return []sd.UnitStatus{
		{Name: "zz.service", LoadState: "loaded", ActiveState: "active", SubState: "running"},
		{Name: "gone.service", LoadState: "not-found", ActiveState: "inactive"},
		{Name: "nginx.service", LoadState: "loaded", ActiveState: "failed", SubState: "failed"},
		{Name: "backup.timer", LoadState: "loaded", ActiveState: "active", SubState: "waiting"},
		{Name: "apparmor.service", LoadState: "loaded", ActiveState: "active", SubState: "exited"},
		{Name: "stopped.service", LoadState: "loaded", ActiveState: "inactive", SubState: "dead"},
	}, nil
}

func (b *fakeBus) job(name string, ch chan<- string) (int, error) {
	b.mu.Lock()
	b.calls = append(b.calls, name)
	b.mu.Unlock()
	if strings.Contains(name, "missing") {
		return 0, errors.New("Unit missing.service not found.")
	}
	ch <- b.result
	return 1, nil
}

func (b *fakeBus) StartUnitContext(_ context.Context, n, _ string, ch chan<- string) (int, error) {
	return b.job("start "+n, ch)
}
func (b *fakeBus) StopUnitContext(_ context.Context, n, _ string, ch chan<- string) (int, error) {
	return b.job("stop "+n, ch)
}
func (b *fakeBus) RestartUnitContext(_ context.Context, n, _ string, ch chan<- string) (int, error) {
	return b.job("restart "+n, ch)
}
func (b *fakeBus) StartTransientUnitContext(_ context.Context, n, _ string, p []sd.Property, ch chan<- string) (int, error) {
	b.mu.Lock()
	b.calls = append(b.calls, "transient "+n)
	b.props = p
	b.mu.Unlock()
	go func() {
		<-b.release
		ch <- b.result
	}()
	return 1, nil
}

func TestUnitsFill(t *testing.T) {
	al := &allow.List{}
	al.Set(proto.Allow{Caps: []string{"systemd"}, Targets: map[string][]string{"systemd": {"backup.timer"}}})
	u := &Units{Bus: &fakeBus{}, Allow: al}
	var st proto.State
	u.Fill(context.Background(), &st)
	for _, n := range []string{"gone.service", "apparmor.service", "stopped.service"} {
		if _, ok := st.Units[n]; ok {
			t.Errorf("%s listed", n)
		}
	}
	if st.Units["nginx.service"]["active"] != "failed" || st.Units["backup.timer"]["sub"] != "waiting" {
		t.Errorf("%v", st.Units)
	}
	if strings.Join(st.FailedUnits, ",") != "a.mount,nginx.service" {
		t.Errorf("failed %v", st.FailedUnits)
	}
	if b := u.Bus.(*fakeBus); strings.Join(b.patterns, ",") != "*.service,backup.timer" {
		t.Errorf("patterns %v", b.patterns)
	}
}

func TestUnitsDo(t *testing.T) {
	b := &fakeBus{result: "done"}
	u := &Units{Bus: b, Allow: &allow.List{}}
	ctx := context.Background()
	if err := u.Do(ctx, "restart", "nginx.service"); err != nil {
		t.Error(err)
	}
	b.result = "failed"
	if err := u.Do(ctx, "start", "nginx.service"); err == nil || err.Error() != "systemd: failed" {
		t.Errorf("got %v", err)
	}
	if err := u.Do(ctx, "stop", "missing.service"); err == nil {
		t.Error("no error for a missing unit")
	}
	if err := u.Do(ctx, "reload", "nginx.service"); err == nil {
		t.Error("an unknown verb was carried out")
	}
}

func TestReboot(t *testing.T) {
	called := make(chan string, 1)
	h := &Host{Delay: 10 * time.Millisecond, Emit: func(string, bool) {},
		Power: func(_ context.Context, m string) error { called <- m; return nil }}
	if err := h.Do(context.Background(), "reboot", "host"); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-called:
		if m != "Reboot" {
			t.Errorf("called %s", m)
		}
	case <-time.After(time.Second):
		t.Error("login1 not called")
	}
}

func TestUpdate(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755)
	os.WriteFile(filepath.Join(root, "usr/bin/apt-get"), nil, 0o755)
	os.WriteFile(filepath.Join(root, "usr/bin/pveversion"), nil, 0o755)
	events := make(chan string, 2)
	b := &fakeBus{result: "done", release: make(chan struct{})}
	h := &Host{Bus: b, Root: root, Emit: func(text string, bad bool) { events <- text }}
	if err := h.Do(context.Background(), "update", "host"); err != nil {
		t.Fatal(err)
	}
	if err := h.Do(context.Background(), "update", "host"); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Errorf("a second update: %v", err)
	}
	var execStart string
	for _, p := range b.props {
		if p.Name == "ExecStart" {
			execStart = p.Value.String()
		}
	}
	if !strings.Contains(execStart, "full-upgrade") || !strings.Contains(execStart, "/usr/bin/apt-get") ||
		!strings.HasSuffix(execStart, "false,)]") { // false = a failure is NOT ignored
		t.Errorf("ExecStart %s", execStart)
	}
	close(b.release)
	select {
	case e := <-events:
		if e != "packages updated" {
			t.Errorf("event %q", e)
		}
	case <-time.After(time.Second):
		t.Fatal("no event at the end")
	}
	// done: a new one may start
	b.release = make(chan struct{})
	close(b.release)
	b.result = "failed"
	if err := h.Do(context.Background(), "update", "host"); err != nil {
		t.Fatal(err)
	}
	if e := <-events; !strings.Contains(e, "failed") {
		t.Errorf("event %q", e)
	}
}

func TestNoPackageManager(t *testing.T) {
	h := &Host{Bus: &fakeBus{}, Root: t.TempDir(), Emit: func(string, bool) {}}
	if err := h.Do(context.Background(), "update", "host"); err == nil {
		t.Error("an update without apt-get or dnf")
	}
}
