package systemd

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// PendingEvery: how often the host's package list is looked at again (the cost is one apt run).
const (
	PendingEvery = 30 * time.Minute
	maxNames     = 12
)

// aptInst: a line of `apt-get -s` that says a package would be installed: "Inst name [old] (new origin [arch])".
var aptInst = regexp.MustCompile(`^Inst (\S+)(?: \[[^\]]*\])? \(([^)]*)\)`)

// ParseInst counts what `apt-get -s upgrade` says it would upgrade: all, those from a security
// archive, and the first names.
func ParseInst(out string) map[string]any {
	names, security, n := []string{}, 0, 0
	for _, line := range strings.Split(out, "\n") {
		m := aptInst.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		n++
		if strings.Contains(strings.ToLower(m[2]), "security") {
			security++
		}
		if len(names) < maxNames {
			names = append(names, m[1])
		}
	}
	return map[string]any{"pending": n, "security": security, "names": names}
}

func (h *Host) simulate(ctx context.Context) (string, error) {
	kind := "upgrade"
	if h.exists("usr/bin/pveversion") {
		kind = "dist-upgrade"
	}
	out, err := exec.CommandContext(ctx, "/usr/bin/apt-get", "-s", "-q", kind).Output()
	return string(out), err
}

// pending: nil without apt or in a container that does not see the host's packages; otherwise the
// count, from the last look when that was not long ago.
func (h *Host) pending(ctx context.Context) map[string]any {
	if (h.Root != "" && h.Root != "/") || !h.exists("usr/bin/apt-get") {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pendingCount != nil && time.Since(h.pendingAt) < PendingEvery {
		return h.pendingCount
	}
	run := h.Simulate
	if run == nil {
		run = h.simulate
	}
	cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	out, err := run(cctx)
	h.pendingAt = time.Now()
	if err != nil {
		return h.pendingCount
	}
	h.pendingCount = ParseInst(out)
	return h.pendingCount
}
