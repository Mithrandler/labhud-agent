// Package allow keeps the last `allow` labhud sent and checks every command against it, before
// any API is touched. labhud checks the same before sending; this is the second check, so even
// a changed labhud cannot make the agent act outside what the admin ticked.
package allow

import (
	"errors"
	"regexp"
	"slices"
	"sync"

	"github.com/Mithrandler/labhud-agent/internal/proto"
)

// Verbs per capability: the same table as labhud's agents.VERBS. Nothing runs a command.
var Verbs = map[string][]string{
	"docker":  {"start", "stop", "restart", "update", "logs", "prune", "inspect"},
	"systemd": {"start", "stop", "restart"},
	"host":    {"reboot", "shutdown", "update"},
	"wol":     {"wake"},
	"pve":     {"start", "shutdown", "reboot"},
	"ptero":   {"start", "stop", "restart"},
}

// Target is the shape of a valid target per capability (labhud's agents.TARGET).
var Target = map[string]*regexp.Regexp{
	"docker":  regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`),
	"systemd": regexp.MustCompile(`^[A-Za-z0-9:_.@-]{1,250}\.(service|timer|socket|target|mount|path)$`),
	"host":    regexp.MustCompile(`^host$`),
	"wol":     regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`),
	"pve":     regexp.MustCompile(`^[1-9][0-9]{2,8}$`),
	"ptero":   regexp.MustCompile(`^[0-9a-f]{8}$`),
}

var ErrNotAllowed = errors.New("not allowed")

type List struct {
	mu      sync.RWMutex
	caps    []string
	targets map[string][]string
	auto    map[string][]string
}

// Set replaces everything with labhud's latest `allow`.
func (l *List) Set(a proto.Allow) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.caps = slices.Clone(a.Caps)
	l.targets = map[string][]string{}
	for c, t := range a.Targets {
		l.targets[c] = slices.Clone(t)
	}
	l.auto = map[string][]string{}
	for c, t := range a.Auto {
		l.auto[c] = slices.Clone(t)
	}
}

// Check: the capability is ticked, the verb is one of its own, the target is ticked and well formed.
func (l *List) Check(cap, verb, target string) error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	re, known := Target[cap]
	if !known || !slices.Contains(Verbs[cap], verb) || !re.MatchString(target) ||
		!slices.Contains(l.caps, cap) || !slices.Contains(l.targets[cap], target) {
		return ErrNotAllowed
	}
	// prune is for the host's images, ticked as the target "images"; that target is nothing else
	if cap == "docker" && (verb == "prune") != (target == PruneTarget) {
		return ErrNotAllowed
	}
	return nil
}

// PruneTarget: docker's prune cleans the host's images, ticked in labhud as this target.
const PruneTarget = "images"

// Auto: is labhud updating this target on its own?
func (l *List) Auto(cap, target string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return slices.Contains(l.auto[cap], target)
}

// Targets gives the ticked targets of one capability.
func (l *List) Targets(cap string) []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return slices.Clone(l.targets[cap])
}

// Has: is the capability ticked? (scan has no targets of its own: it reads docker's)
func (l *List) Has(cap string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return slices.Contains(l.caps, cap)
}
