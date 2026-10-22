// Package allow keeps the last `allow` labhud sent and checks every command against it, before
// any API is touched. labhud checks the same before sending; this is the second check, so even
// a changed labhud cannot make the agent act outside what the admin ticked.
package allow

import (
	"errors"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/Mithrandler/labhud-agent/internal/proto"
)

// Verbs per capability: the same table as labhud's agents.VERBS. Nothing runs a command.
var Verbs = map[string][]string{
	"docker": {"start", "stop", "restart", "update", "logs", "prune", "inspect", "inventory", "prune-dangling", "prune-networks", "prune-volumes", "follow", "stats",
		"rm-image", "rm-network", "rm-volume", "pull", "network-inspect", "volume-ls", "volume-read"},
	"systemd":  {"start", "stop", "restart"},
	"host":     {"reboot", "shutdown", "update"},
	"wol":      {"wake"},
	"terminal": {"shell"},
	"stacks":   {"deploy", "redeploy", "restart", "down", "show", "read", "validate", "save", "version", "restore"},
	"pve":      {"start", "shutdown", "reboot", "config", "snap-list", "backup-list", "task-list", "snap-create", "snap-rollback", "snap-delete"},
	"ptero":    {"start", "stop", "restart"},
}

// Target is the shape of a valid target per capability (labhud's agents.TARGET).
var Target = map[string]*regexp.Regexp{
	"docker":   regexp.MustCompile(`^(volume:)?[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`),
	"systemd":  regexp.MustCompile(`^[A-Za-z0-9:_.@-]{1,250}\.(service|timer|socket|target|mount|path)$`),
	"host":     regexp.MustCompile(`^host$`),
	"wol":      regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`),
	"stacks":   regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`),
	"terminal": regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`),
	"pve":      regexp.MustCompile(`^[1-9][0-9]{2,8}$`),
	"ptero":    regexp.MustCompile(`^[0-9a-f]{8}$`),
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
	// the host verbs are for the target "images" (the host's Docker, not a container), and that
	// target takes nothing else
	if cap == "docker" && !dockerKinds(verb, target) {
		return ErrNotAllowed
	}
	if cap == "terminal" && target == PruneTarget { // "images" is no container
		return ErrNotAllowed
	}
	return nil
}

// VolumeTarget: a volume ticked for browsing is the target "volume:<name>"; the two volume verbs are
// for those targets and for nothing else (a container takes neither, nor does "images").
const VolumeTarget = "volume:"

// VolumeVerb: a docker verb that reads inside a volume, read only.
func VolumeVerb(verb string) bool { return verb == "volume-ls" || verb == "volume-read" }

// dockerKinds: the verb and the target are of the same kind (a container, the host's Docker, a volume).
func dockerKinds(verb, target string) bool {
	isVolume := strings.HasPrefix(target, VolumeTarget)
	if VolumeVerb(verb) != isVolume {
		return false
	}
	return isVolume || HostVerb(verb) == (target == PruneTarget)
}

// PruneTarget: the host's Docker (its images, volumes and networks), ticked in labhud as this
// target: the verbs below are for it and for nothing else.
const PruneTarget = "images"

// HostVerb: a docker verb about the host's images, volumes and networks, not about a container.
func HostVerb(verb string) bool {
	switch verb {
	case "prune", "prune-dangling", "prune-networks", "prune-volumes", "inventory",
		"rm-image", "rm-network", "rm-volume", "pull", "network-inspect":
		return true
	}
	return false
}

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

// The argument of each verb that takes one (every other verb takes none).
var (
	imageArg   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,199}$`)
	versionArg = regexp.MustCompile(`^[0-9]{1,12}$`)
	nameArg    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	snapArg    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,39}$`) // Proxmox's own rule for a snapshot name
)

const MaxPath = 400

// CleanPath turns a path in a volume into its plain form ("/", "/a/b"): no "..", no control
// characters, not too long. An empty path is the root.
func CleanPath(p string) (string, error) {
	if len(p) > MaxPath {
		return "", ErrNotAllowed
	}
	for _, r := range p {
		if r < 32 || r == 127 {
			return "", ErrNotAllowed
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", ErrNotAllowed
		}
	}
	return path.Clean("/" + p), nil
}

// CheckArg: the argument has the shape its verb takes, and a verb that takes none gets none. The
// agent checks it as labhud does, before any API is touched.
func CheckArg(verb, arg string) error {
	switch verb {
	case "rm-image", "pull":
		if !imageArg.MatchString(arg) {
			return ErrNotAllowed
		}
	case "rm-network", "rm-volume", "network-inspect":
		if !nameArg.MatchString(arg) {
			return ErrNotAllowed
		}
	case "snap-create", "snap-rollback", "snap-delete":
		if !snapArg.MatchString(arg) {
			return ErrNotAllowed
		}
	case "version", "restore":
		if !versionArg.MatchString(arg) {
			return ErrNotAllowed
		}
	case "volume-ls", "volume-read":
		clean, err := CleanPath(arg)
		if err != nil || (verb == "volume-read" && clean == "/") {
			return ErrNotAllowed
		}
	default:
		if arg != "" {
			return ErrNotAllowed
		}
	}
	return nil
}
