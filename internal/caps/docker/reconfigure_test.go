package docker

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func strs(s ...string) *[]string { return &s }

func TestChangeCheck(t *testing.T) {
	long := strings.Repeat("x", maxEnvVal+1)
	for _, tc := range []struct {
		name string
		ch   Change
		bad  string // part of the error; "" is fine
	}{
		{"empty", Change{}, "nothing"},
		{"env ok", Change{EnvSet: map[string]string{"A_1": "v"}, EnvUnset: []string{"B"}}, ""},
		{"env bad name", Change{EnvSet: map[string]string{"1A": "v"}}, "variable name"},
		{"env long", Change{EnvSet: map[string]string{"A": long}}, "too long"},
		{"env both", Change{EnvSet: map[string]string{"A": "1"}, EnvUnset: []string{"A"}}, "both"},
		{"ports ok", Change{Ports: strs("8080:80", "127.0.0.1:53:53/udp", ":3000")}, ""},
		{"ports bad", Change{Ports: strs("80")}, "port mapping"},
		{"ports range", Change{Ports: strs("70000:80")}, "out of range"},
		{"ports address", Change{Ports: strs("300.1.1.1:80:80")}, "address"},
		{"ports twice", Change{Ports: strs("80:80", "80:80")}, "twice"},
		{"volumes ok", Change{Volumes: strs("/srv:/srv:ro", "data:/data")}, ""},
		{"volumes relative target", Change{Volumes: strs("/srv:srv")}, "not a volume"},
		{"volumes dotdot", Change{Volumes: strs("/srv/../etc:/x")}, "not a volume"},
		{"volumes same target", Change{Volumes: strs("/a:/x", "/b:/x")}, "two volumes"},
		{"restart ok", Change{Restart: new(string)}, "restart policy"}, // "" is none
		{"restart bad", Change{Restart: &[]string{"sometimes"}[0]}, "restart policy"},
		{"restart retry", Change{Restart: &[]string{"on-failure:5"}[0]}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ch.check()
			if tc.bad == "" && err != nil || tc.bad != "" && (err == nil || !strings.Contains(err.Error(), tc.bad)) {
				t.Fatalf("got %v, want %q", err, tc.bad)
			}
		})
	}
}

func TestChangeApply(t *testing.T) {
	create := map[string]any{
		"Env":          []any{"KEEP=1", "CHANGE=old", "DROP=x"},
		"ExposedPorts": map[string]any{"9000/tcp": map[string]any{}},
		"HostConfig":   map[string]any{"Binds": []any{"/old:/old"}, "NetworkMode": "front"},
	}
	ch := Change{EnvSet: map[string]string{"CHANGE": "new", "ADD": "1"}, EnvUnset: []string{"DROP"},
		Ports: strs("8080:80", "127.0.0.1:53:53/udp"), Volumes: strs("data:/data"), Restart: &[]string{"on-failure:3"}[0]}
	ch.apply(create)
	if got := fmt.Sprint(create["Env"]); got != "[KEEP=1 CHANGE=new ADD=1]" {
		t.Errorf("env %s", got)
	}
	host := create["HostConfig"].(map[string]any)
	if fmt.Sprint(host["Binds"]) != "[data:/data]" || host["NetworkMode"] != "front" {
		t.Errorf("host %v", host)
	}
	if got := fmt.Sprint(host["PortBindings"]); got != "map[53/udp:[map[HostIp:127.0.0.1 HostPort:53]] 80/tcp:[map[HostIp: HostPort:8080]]]" {
		t.Errorf("bindings %s", got)
	}
	if got := fmt.Sprint(create["ExposedPorts"]); got != "map[53/udp:map[] 80/tcp:map[] 9000/tcp:map[]]" {
		t.Errorf("exposed %s", got)
	}
	if got := fmt.Sprint(host["RestartPolicy"]); got != "map[MaximumRetryCount:3 Name:on-failure]" {
		t.Errorf("restart %s", got)
	}
}

func TestReconfigure(t *testing.T) {
	saved := StartWait
	StartWait = 10 * time.Millisecond
	t.Cleanup(func() { StartWait = saved })
	for _, tc := range []struct {
		name  string
		e     *engine
		files string
		err   string
	}{
		{"made again", &engine{newRuns: true, sameImage: true}, `{"env_set":{"TOKEN":"s3cret"},"ports":["8080:80"]}`, ""},
		{"restart alone is live", &engine{sameImage: true}, `{"restart":"always"}`, ""},
		{"the new one does not stay up", &engine{newRuns: false, sameImage: true}, `{"ports":["8080:80"]}`, "does not stay up"},
		{"a newer image is on the host", &engine{newRuns: true}, `{"ports":["8080:80"]}`, "update the container first"},
		{"bad change", &engine{sameImage: true}, `{"ports":["x"]}`, "port mapping"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := tc.e.start(t)
			out, err := d.Deploy(t.Context(), "reconfigure", "web", map[string]string{"config": tc.files})
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("got %v, want %q", err, tc.err)
				}
				if strings.Contains(err.Error(), "s3cret") {
					t.Error("a value in an error")
				}
			} else if err != nil {
				t.Fatalf("%v\n%s", err, tc.e.seen())
			}
			calls := tc.e.seen()
			switch tc.name {
			case "made again":
				for _, want := range []string{"/stop?t=20", "rename?name=web-labhud-old", "POST /containers/create?name=web", "POST /containers/newid/start?", "DELETE /containers/oldid0000000000?"} {
					if !strings.Contains(calls, want) {
						t.Errorf("no %q in:\n%s", want, calls)
					}
				}
				if got := fmt.Sprint(tc.e.created["Env"]); !strings.Contains(got, "TOKEN=s3cret") || !strings.Contains(got, "MINE=1") {
					t.Errorf("env %s", got)
				}
				if tc.e.created["Image"] != "nginx:1" || !strings.Contains(out, "made again") {
					t.Errorf("image %v out %q", tc.e.created["Image"], out)
				}
			case "restart alone is live":
				if strings.Contains(calls, "create") || !strings.Contains(calls, "POST /containers/oldid0000000000/update?") {
					t.Errorf("a live change, not a new container:\n%s", calls)
				}
			case "the new one does not stay up", "a newer image is on the host", "bad change":
				if tc.name != "bad change" && tc.name != "a newer image is on the host" && !strings.Contains(calls, "rename?name=web&") && !strings.Contains(calls, "rename?name=web") {
					t.Errorf("the old one is not put back:\n%s", calls)
				}
				if tc.name != "the new one does not stay up" && strings.Contains(calls, "/stop") {
					t.Errorf("nothing may be stopped:\n%s", calls)
				}
			}
		})
	}
}

func TestConfigView(t *testing.T) {
	d := (&engine{}).start(t)
	out, err := d.configView(t.Context(), "web")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"env":["MINE","PATH"]`) || strings.Contains(out, "=1") || !strings.Contains(out, `"volumes":["/srv:/srv"]`) || !strings.Contains(out, `"restart":"no"`) {
		t.Errorf("view %s", out)
	}
}
