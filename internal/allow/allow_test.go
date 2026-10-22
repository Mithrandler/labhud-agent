package allow

import (
	"strings"
	"testing"

	"github.com/Mithrandler/labhud-agent/internal/proto"
)

func TestCheck(t *testing.T) {
	var l List
	if l.Check("docker", "restart", "jellyfin") == nil {
		t.Fatal("allowed before any allow")
	}
	l.Set(proto.Allow{Caps: []string{"docker", "pve", "stacks", "terminal"}, Targets: map[string][]string{
		"docker": {"jellyfin", "images"}, "stacks": {"web"}, "terminal": {"jellyfin", "images"}, "pve": {"101"}, "systemd": {"nginx.service"}}})
	ok := [][3]string{{"docker", "restart", "jellyfin"}, {"pve", "shutdown", "101"}, {"stacks", "deploy", "web"}, {"terminal", "shell", "jellyfin"}, {"docker", "follow", "jellyfin"}, {"stacks", "down", "web"}, {"docker", "prune", "images"},
		{"docker", "inventory", "images"}, {"docker", "prune-dangling", "images"}, {"docker", "prune-networks", "images"}, {"docker", "prune-volumes", "images"}}
	no := [][3]string{
		{"docker", "restart", "plex"},           // target not ticked
		{"docker", "exec", "jellyfin"},          // no such verb
		{"pve", "stop", "101"},                  // hard stop is not a verb
		{"systemd", "restart", "nginx.service"}, // capability not ticked
		{"shell", "run", "ls"},                  // no such capability
		{"host", "reboot", "host"},              // not ticked
		{"docker", "prune", "jellyfin"},         // prune is for the images only
		{"terminal", "shell", "plex"},           // not ticked for the terminal
		{"terminal", "shell", "images"},         // "images" is no container
		{"terminal", "exec", "jellyfin"},
		{"docker", "follow", "images"},
		{"stacks", "deploy", "Web"}, // a stack's name is lowercase
		{"stacks", "deploy", "../etc"},
		{"stacks", "exec", "web"},           // no such verb
		{"stacks", "deploy", "api"},         // not ticked
		{"docker", "stop", "images"},        // and "images" is no container
		{"docker", "inventory", "jellyfin"}, // the host verbs are for the images target only
		{"docker", "prune-volumes", "jellyfin"},
		{"docker", "prune-networks", "jellyfin"},
	}
	for _, c := range ok {
		if err := l.Check(c[0], c[1], c[2]); err != nil {
			t.Errorf("%v refused", c)
		}
	}
	for _, c := range no {
		if l.Check(c[0], c[1], c[2]) == nil {
			t.Errorf("%v allowed", c)
		}
	}
	l.Set(proto.Allow{Caps: []string{}, Targets: map[string][]string{}})
	if l.Check("docker", "restart", "jellyfin") == nil {
		t.Error("a new allow did not replace the old one")
	}
}

func TestMalformedTargetRefusedEvenIfListed(t *testing.T) {
	var l List
	l.Set(proto.Allow{Caps: []string{"docker"}, Targets: map[string][]string{"docker": {"a;rm -rf /"}}})
	if l.Check("docker", "start", "a;rm -rf /") == nil {
		t.Error("malformed target allowed")
	}
}

func TestCheckArgSnapshotNames(t *testing.T) {
	for _, ok := range []string{"before-upgrade", "a", "S_1", strings.Repeat("a", 40)} {
		for _, verb := range []string{"snap-create", "snap-rollback", "snap-delete"} {
			if CheckArg(verb, ok) != nil {
				t.Errorf("%s %q refused", verb, ok)
			}
		}
	}
	for _, bad := range []string{"", "1abc", "-x", "a b", "a;b", "a/../b", strings.Repeat("a", 41), "a\n"} {
		if CheckArg("snap-create", bad) == nil {
			t.Errorf("snap-create %q allowed", bad)
		}
	}
	for _, verb := range []string{"config", "snap-list", "backup-list", "task-list"} {
		if CheckArg(verb, "x") == nil || CheckArg(verb, "") != nil {
			t.Errorf("%s takes no argument", verb)
		}
	}
}
