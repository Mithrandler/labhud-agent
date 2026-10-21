// Package systemd gives two capabilities over D-Bus, never through systemctl or a shell:
//
//   - systemd: the host's services with their state; start, stop, restart one;
//   - host: reboot or shut down the host (login1), and update its packages in a transient unit
//     (labhud-update.service), which survives the agent restarting during the update.
package systemd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	sd "github.com/coreos/go-systemd/v22/dbus"
	godbus "github.com/godbus/dbus/v5"

	"github.com/Mithrandler/labhud-agent/internal/allow"
	"github.com/Mithrandler/labhud-agent/internal/caps"
	"github.com/Mithrandler/labhud-agent/internal/proto"
)

const (
	MaxUnits   = 200
	UpdateUnit = "labhud-update.service"
	UpdateMax  = 2 * time.Hour
)

// Bus is the part of systemd's D-Bus API used here (go-systemd's *dbus.Conn has it).
type Bus interface {
	ListUnitsByPatternsContext(ctx context.Context, states, patterns []string) ([]sd.UnitStatus, error)
	StartUnitContext(ctx context.Context, name, mode string, ch chan<- string) (int, error)
	StopUnitContext(ctx context.Context, name, mode string, ch chan<- string) (int, error)
	RestartUnitContext(ctx context.Context, name, mode string, ch chan<- string) (int, error)
	StartTransientUnitContext(ctx context.Context, name, mode string, props []sd.Property, ch chan<- string) (int, error)
}

// Connect opens the system bus; nil when there is none (a container without /run/dbus).
func Connect(ctx context.Context) Bus {
	c, err := sd.NewSystemConnectionContext(ctx)
	if err != nil {
		return nil
	}
	return c
}

// --- systemd: units ---

type Units struct {
	Bus   Bus
	Allow *allow.List // the ticked units are always listed, even past MaxUnits
}

func (u *Units) Name() string { return "systemd" }

func (u *Units) Fill(ctx context.Context, st *proto.State) {
	ticked := u.Allow.Targets("systemd")
	list, err := u.Bus.ListUnitsByPatternsContext(ctx, nil, append([]string{"*.service"}, ticked...))
	if err != nil {
		return
	}
	// ticked first, then the rest by name, up to MaxUnits
	slices.SortFunc(list, func(a, b sd.UnitStatus) int {
		ta, tb := slices.Contains(ticked, a.Name), slices.Contains(ticked, b.Name)
		if ta != tb {
			if ta {
				return -1
			}
			return 1
		}
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	st.FailedUnits = []string{}
	if failed, err := u.Bus.ListUnitsByPatternsContext(ctx, []string{"failed"}, nil); err == nil {
		for _, s := range failed {
			if len(st.FailedUnits) < MaxUnits {
				st.FailedUnits = append(st.FailedUnits, s.Name)
			}
		}
		slices.Sort(st.FailedUnits)
	}
	st.Units = map[string]map[string]any{}
	for _, s := range list {
		if len(st.Units) >= MaxUnits {
			break
		}
		// what someone would press a button for: running or failed; not the boot-time one-shots
		// (active/exited) nor what is stopped anyway. A ticked unit is always there.
		useful := s.LoadState == "loaded" && (s.SubState == "running" || s.ActiveState == "failed")
		if !useful && !slices.Contains(ticked, s.Name) {
			continue
		}
		st.Units[s.Name] = map[string]any{"active": s.ActiveState, "sub": s.SubState, "description": s.Description}
	}
}

// wait reads the job's result ("done", "failed", "canceled", "timeout", "dependency", "skipped").
func wait(ctx context.Context, ch <-chan string) error {
	select {
	case r := <-ch:
		if r == "done" {
			return nil
		}
		return fmt.Errorf("systemd: %s", r)
	case <-ctx.Done():
		return errors.New("systemd: still running")
	}
}

func (u *Units) Do(ctx context.Context, verb, target string) error {
	ch := make(chan string, 1)
	var err error
	switch verb {
	case "start":
		_, err = u.Bus.StartUnitContext(ctx, target, "replace", ch)
	case "stop":
		_, err = u.Bus.StopUnitContext(ctx, target, "replace", ch)
	case "restart":
		_, err = u.Bus.RestartUnitContext(ctx, target, "replace", ch)
	default:
		return caps.ErrNoVerb
	}
	if err != nil {
		return err
	}
	return wait(ctx, ch)
}

// --- host: reboot, shut down, update ---

type Host struct {
	Bus   Bus
	Root  string                      // where the host's / is, to find its package manager
	Emit  func(text string, bad bool) // the end of an update, for labhud's timeline
	Power func(ctx context.Context, method string) error
	Delay time.Duration // between the answer and the reboot, so the answer leaves first

	mu       sync.Mutex
	updating bool
}

// NewHost: Power calls login1 over its own bus connection.
func NewHost(bus Bus, root string, emit func(string, bool)) *Host {
	return &Host{Bus: bus, Root: root, Emit: emit, Power: login1, Delay: 3 * time.Second}
}

func login1(ctx context.Context, method string) error {
	c, err := godbus.ConnectSystemBus()
	if err != nil {
		return err
	}
	defer c.Close()
	return c.Object("org.freedesktop.login1", "/org/freedesktop/login1").
		CallWithContext(ctx, "org.freedesktop.login1.Manager."+method, 0, false).Err
}

func (h *Host) Name() string { return "host" }

func (h *Host) Fill(context.Context, *proto.State) {}

// execCmd is systemd's (sasb): path, argv, and whether a failure is IGNORED (the "-" prefix).
// go-systemd calls that bool UncleanIsFailure, which is the opposite: with true, an update that
// failed came back "done" (tried on a real systemd, 15 Oct 2026). Keep it false.
type execCmd struct {
	Path          string
	Args          []string
	IgnoreFailure bool
}

func prop(name string, v any) sd.Property {
	return sd.Property{Name: name, Value: godbus.MakeVariant(v)}
}

func (h *Host) exists(p string) bool {
	_, err := os.Stat(filepath.Join(h.Root, p))
	return err == nil
}

// UpdateCommands: the package manager's commands, without a shell. Proxmox wants full-upgrade.
func (h *Host) UpdateCommands() (pre, main []string, err error) {
	switch {
	case h.exists("usr/bin/apt-get"):
		kind := "upgrade"
		if h.exists("usr/bin/pveversion") {
			kind = "full-upgrade"
		}
		return []string{"/usr/bin/apt-get", "-q", "update"},
			[]string{"/usr/bin/apt-get", "-y", "-q", "-o", "Dpkg::Options::=--force-confdef",
				"-o", "Dpkg::Options::=--force-confold", kind}, nil
	case h.exists("usr/bin/dnf"):
		return nil, []string{"/usr/bin/dnf", "-y", "upgrade"}, nil
	}
	return nil, nil, errors.New("no apt-get or dnf on this host")
}

func (h *Host) Do(ctx context.Context, verb, _ string) error {
	switch verb {
	case "reboot", "shutdown":
		method := map[string]string{"reboot": "Reboot", "shutdown": "PowerOff"}[verb]
		go func() {
			time.Sleep(h.Delay)
			c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := h.Power(c, method); err != nil {
				h.Emit(fmt.Sprintf("%s failed: %v", verb, err), true)
			}
		}()
		return nil
	case "update":
		return h.update(ctx)
	}
	return caps.ErrNoVerb
}

func (h *Host) update(ctx context.Context) error {
	pre, cmd, err := h.UpdateCommands()
	if err != nil {
		return err
	}
	h.mu.Lock()
	if h.updating {
		h.mu.Unlock()
		return errors.New("an update is already running")
	}
	h.updating = true
	h.mu.Unlock()
	props := []sd.Property{
		sd.PropDescription("labhud: package update"),
		sd.PropType("oneshot"),
		prop("CollectMode", "inactive-or-failed"),
		prop("Environment", []string{"DEBIAN_FRONTEND=noninteractive"}),
		prop("ExecStart", []execCmd{{cmd[0], cmd, false}}),
	}
	if pre != nil {
		props = append(props, prop("ExecStartPre", []execCmd{{pre[0], pre, false}}))
	}
	ch := make(chan string, 1)
	// the job outlives this command: its own context, not the command's
	if _, err := h.Bus.StartTransientUnitContext(context.Background(), UpdateUnit, "fail", props, ch); err != nil {
		h.mu.Lock()
		h.updating = false
		h.mu.Unlock()
		return err
	}
	go func() {
		wctx, cancel := context.WithTimeout(context.Background(), UpdateMax)
		defer cancel()
		err := wait(wctx, ch)
		h.mu.Lock()
		h.updating = false
		h.mu.Unlock()
		if err != nil {
			h.Emit(fmt.Sprintf("package update failed (%v): journalctl -u %s", err, UpdateUnit), true)
		} else {
			h.Emit("packages updated", false)
		}
	}()
	return nil
}
