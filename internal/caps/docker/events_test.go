package docker

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/allow"
	"github.com/Mithrandler/labhud-agent/internal/proto"
)

func TestCrashes(t *testing.T) {
	var c crashes
	t0 := time.Unix(1_000_000, 0)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	kind := func(name, action, exit string, s int) string {
		if ev := c.see(name, action, exit, at(s)); ev != nil {
			if ev.Target != name || !ev.Bad {
				t.Fatalf("%+v", ev)
			}
			return ev.Kind
		}
		return ""
	}
	if k := kind("web", "die", "0", 0); k != "" {
		t.Errorf("exit 0: %q", k)
	}
	kind("web", "kill", "", 10)
	if k := kind("web", "die", "137", 15); k != "" {
		t.Errorf("a stop asked for: %q", k)
	}
	if k := kind("web", "die", "1", 100); k != "crash" {
		t.Errorf("crash: %q", k)
	}
	if k := kind("db", "oom", "", 100); k != "oom" {
		t.Errorf("oom: %q", k)
	}
	if k := kind("db", "die", "137", 101); k != "" {
		t.Errorf("the die after an oom: %q", k)
	}
	if k := kind("web", "die", "1", 200); k != "crash" {
		t.Errorf("second crash: %q", k)
	}
	if k := kind("web", "die", "1", 300); k != "loop" {
		t.Errorf("third in 10 minutes: %q", k)
	}
	if k := kind("web", "die", "1", 400); k != "" {
		t.Errorf("quiet after the loop: %q", k)
	}
	if k := kind("web", "die", "1", 300+31*60); k != "crash" {
		t.Errorf("after the quiet, alone in its window: %q", k)
	}
}

func TestFigures(t *testing.T) {
	var s engineStats
	s.CPUStats.CPUUsage.TotalUsage, s.PreCPUStats.CPUUsage.TotalUsage = 3_000, 1_000
	s.CPUStats.SystemUsage, s.PreCPUStats.SystemUsage = 20_000, 10_000
	s.CPUStats.OnlineCPUs = 4
	s.MemoryStats.Usage, s.MemoryStats.Limit = 300<<20, 1<<30
	s.MemoryStats.Stats = map[string]uint64{"inactive_file": 44 << 20}
	s.Networks = map[string]struct {
		RxBytes uint64 `json:"rx_bytes"`
		TxBytes uint64 `json:"tx_bytes"`
	}{"eth0": {RxBytes: 3000, TxBytes: 600}}
	t0 := time.Unix(1_000_000, 0)
	u := figures(s, nil, t0)
	if u.cpu != 80 || u.mem != 256<<20 || u.memPct != 25 || u.rates {
		t.Fatalf("%+v", u)
	}
	s.Networks["eth0"] = struct {
		RxBytes uint64 `json:"rx_bytes"`
		TxBytes uint64 `json:"tx_bytes"`
	}{RxBytes: 6000, TxBytes: 900}
	v := figures(s, &u, t0.Add(30*time.Second))
	if !v.rates || v.rx != 100 || v.tx != 10 {
		t.Fatalf("%+v", v)
	}
	e := map[string]any{}
	v.put(e)
	if e["net_rx"] != 100.0 || e["cpu"] != 80.0 {
		t.Fatalf("%v", e)
	}
}

func TestDetailsKeepNoSecrets(t *testing.T) {
	var c inspected
	c.Config.Image = "vaultwarden/server:1.32"
	c.Config.Env = []string{"ADMIN_TOKEN=hunter2", "TZ=Europe/Bucharest"}
	c.Config.Labels = map[string]string{"traefik.http.middlewares.a.basicauth.users": "u:$hash", "com.docker.compose.project": "vw"}
	c.Config.Cmd = []string{"--password", "x"}
	c.NetworkSettings.Ports = map[string][]struct{ HostIp, HostPort string }{
		"80/tcp": {{"0.0.0.0", "8812"}, {"::", "8812"}}, "3012/tcp": nil}
	d := details(c)
	b, _ := json.Marshal(d)
	for _, s := range []string{"hunter2", "Europe/Bucharest", "$hash", "--password"} {
		if strings.Contains(string(b), s) {
			t.Errorf("%q in %s", s, b)
		}
	}
	if strings.Join(d.Env, ",") != "ADMIN_TOKEN,TZ" || strings.Join(d.Ports, ",") != "3012/tcp,8812→80/tcp" || d.Restart != "no" {
		t.Errorf("%+v", d)
	}
	if d.Labels["com.docker.compose.project"] != "vw" {
		t.Errorf("%v", d.Labels)
	}
}

func TestAutoLabels(t *testing.T) {
	al := &allow.List{}
	al.Set(proto.Allow{Caps: []string{"docker"}, Targets: map[string][]string{"docker": {"web", "db"}},
		Auto: map[string][]string{"docker": {"web"}}})
	d := &Docker{Allow: al, AutoLabels: map[string]string{"dockhand.update": "false"}}
	web := map[string]any{"Labels": map[string]any{"a": "1"}}
	d.autoLabels(web, "web")
	if web["Labels"].(map[string]any)["dockhand.update"] != "false" {
		t.Errorf("auto: %v", web["Labels"])
	}
	db := map[string]any{"Labels": map[string]any{"dockhand.update": "false", "a": "1"}}
	d.autoLabels(db, "db") // no longer labhud's: the label goes, the rest stays
	if _, ok := db["Labels"].(map[string]any)["dockhand.update"]; ok || db["Labels"].(map[string]any)["a"] != "1" {
		t.Errorf("not auto: %v", db["Labels"])
	}
	none := map[string]any{}
	(&Docker{Allow: al}).autoLabels(none, "web") // no AutoLabels on this host: untouched
	if _, ok := none["Labels"]; ok {
		t.Errorf("%v", none)
	}
}

func TestOwnLabels(t *testing.T) {
	got := own(map[string]string{"labhud.name": "Jellyfin", "labhud.url": "https://jf", "traefik.enable": "true"})
	if len(got) != 2 || got["labhud.name"] != "Jellyfin" {
		t.Errorf("%v", got)
	}
}
