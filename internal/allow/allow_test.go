package allow

import (
	"testing"

	"github.com/Mithrandler/labhud-agent/internal/proto"
)

func TestCheck(t *testing.T) {
	var l List
	if l.Check("docker", "restart", "jellyfin") == nil {
		t.Fatal("allowed before any allow")
	}
	l.Set(proto.Allow{Caps: []string{"docker", "pve", "stacks"}, Targets: map[string][]string{
		"docker": {"jellyfin", "images"}, "stacks": {"web"}, "pve": {"101"}, "systemd": {"nginx.service"}}})
	ok := [][3]string{{"docker", "restart", "jellyfin"}, {"pve", "shutdown", "101"}, {"stacks", "deploy", "web"}, {"stacks", "down", "web"}, {"docker", "prune", "images"},
		{"docker", "inventory", "images"}, {"docker", "prune-dangling", "images"}, {"docker", "prune-networks", "images"}, {"docker", "prune-volumes", "images"}}
	no := [][3]string{
		{"docker", "restart", "plex"},           // target not ticked
		{"docker", "exec", "jellyfin"},          // no such verb
		{"pve", "stop", "101"},                  // hard stop is not a verb
		{"systemd", "restart", "nginx.service"}, // capability not ticked
		{"shell", "run", "ls"},                  // no such capability
		{"host", "reboot", "host"},              // not ticked
		{"docker", "prune", "jellyfin"},         // prune is for the images only
		{"stacks", "deploy", "Web"},             // a stack's name is lowercase
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
