package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/caps"
	"github.com/Mithrandler/labhud-agent/internal/proto"
)

func waitEvent(t *testing.T, got chan proto.Event) proto.Event {
	t.Helper()
	select {
	case ev := <-got:
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("no event")
	}
	return proto.Event{}
}

func updateWith(t *testing.T, e *engine, opt caps.UpdateOptions, scan func(context.Context, string) (int, error)) proto.Event {
	t.Helper()
	saved := StartWait
	StartWait = 10 * time.Millisecond
	t.Cleanup(func() { StartWait = saved })
	d := e.start(t)
	d.Scan = scan
	got := make(chan proto.Event, 1)
	d.Send = func(ev proto.Event) { got <- ev }
	if err := d.UpdateWith("web", opt); err != nil {
		t.Fatal(err)
	}
	return waitEvent(t, got)
}

// The image "nginx:1" comes from Docker Hub: a Hub login goes with its pull, as X-Registry-Auth.
func TestUpdateWithLogin(t *testing.T) {
	e := &engine{newRuns: true}
	ev := updateWith(t, e, caps.UpdateOptions{Registry: "docker.io", Login: &proto.Login{Username: "demo", Password: "s3cret"}}, nil)
	if ev.Bad {
		t.Fatalf("%+v", ev)
	}
	if len(e.auth) != 1 || e.auth[0] == "" {
		t.Fatalf("auth %q", e.auth)
	}
	raw, err := base64.URLEncoding.DecodeString(e.auth[0])
	var got map[string]string
	if err != nil || json.Unmarshal(raw, &got) != nil {
		t.Fatalf("not URL-safe base64 JSON: %q", e.auth[0])
	}
	if got["username"] != "demo" || got["password"] != "s3cret" || got["serveraddress"] != "https://index.docker.io/v1/" {
		t.Errorf("%v", got)
	}
	if strings.Contains(ev.Text, "s3cret") {
		t.Error("the token is in the event")
	}
}

// A login for another registry than the image's never reaches the engine (it would hand it to
// the image's registry).
func TestUpdateWithLoginOfAnotherRegistry(t *testing.T) {
	e := &engine{newRuns: true}
	ev := updateWith(t, e, caps.UpdateOptions{Registry: "ghcr.io", Login: &proto.Login{Username: "demo", Password: "s3cret"}}, nil)
	if ev.Bad || len(e.auth) != 1 || e.auth[0] != "" {
		t.Fatalf("event %+v auth %q", ev, e.auth)
	}
}

func TestUpdateWithoutLogin(t *testing.T) {
	e := &engine{newRuns: true}
	updateWith(t, e, caps.UpdateOptions{}, nil)
	if len(e.auth) != 1 || e.auth[0] != "" {
		t.Fatalf("auth %q", e.auth)
	}
}

func scans(m map[string]int, err error) func(context.Context, string) (int, error) {
	return func(_ context.Context, id string) (int, error) {
		if err != nil && id == "sha256:new" {
			return 0, err
		}
		return m[id], nil
	}
}

func TestHoldCritical(t *testing.T) {
	for _, tc := range []struct {
		name string
		scan func(context.Context, string) (int, error)
		hold bool
		held string // "" = updated
	}{
		{"more critical: held", scans(map[string]int{"sha256:old": 1, "sha256:new": 3}, nil), true,
			"web: update held: 3 critical CVEs in the new image (1 now)"},
		{"as many: updated", scans(map[string]int{"sha256:old": 2, "sha256:new": 2}, nil), true, ""},
		{"fewer: updated", scans(map[string]int{"sha256:old": 4, "sha256:new": 0}, nil), true, ""},
		{"no scan of the new one: held", scans(nil, errors.New("db download failed")), true,
			"web: update held: the new image could not be scanned (db download failed)"},
		{"not asked: updated", scans(map[string]int{"sha256:new": 9}, nil), false, ""},
		{"no scanner: updated", nil, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &engine{newRuns: true}
			ev := updateWith(t, e, caps.UpdateOptions{HoldCritical: tc.hold}, tc.scan)
			calls := e.seen()
			if tc.held == "" {
				if ev.Bad || ev.Kind != "update" || !strings.Contains(calls, "/stop") {
					t.Fatalf("not updated: %+v\n%s", ev, calls)
				}
				return
			}
			if ev.Text != tc.held || !ev.Bad || ev.Kind != "held" || ev.Target != "web" || ev.Cap != "docker" {
				t.Fatalf("event %+v", ev)
			}
			if strings.Contains(calls, "/stop") || strings.Contains(calls, "/containers/create") {
				t.Errorf("held, yet touched the container:\n%s", calls)
			}
		})
	}
}
