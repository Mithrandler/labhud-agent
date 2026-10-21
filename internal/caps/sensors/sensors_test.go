package sensors

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, root, p, s string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fakeHost(t *testing.T) string {
	root := t.TempDir()
	write(t, root, "proc/stat", "cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 2 3 4\n")
	write(t, root, "proc/meminfo", "MemTotal:       1000 kB\nMemFree:         100 kB\nMemAvailable:    400 kB\n")
	write(t, root, "proc/loadavg", "0.42 0.30 0.20 1/100 1234\n")
	write(t, root, "proc/uptime", "3600.75 7000.00\n")
	// an unrelated sensor first, then coretemp with a package reading
	write(t, root, "sys/class/hwmon/hwmon0/name", "acpitz\n")
	write(t, root, "sys/class/hwmon/hwmon0/temp1_label", "Package id 0\n")
	write(t, root, "sys/class/hwmon/hwmon0/temp1_input", "99000\n")
	write(t, root, "sys/class/hwmon/hwmon1/name", "coretemp\n")
	write(t, root, "sys/class/hwmon/hwmon1/temp2_label", "Core 0\n")
	write(t, root, "sys/class/hwmon/hwmon1/temp2_input", "51000\n")
	write(t, root, "sys/class/hwmon/hwmon1/temp1_label", "Package id 0\n")
	write(t, root, "sys/class/hwmon/hwmon1/temp1_input", "48250\n")
	write(t, root, "sys/class/powercap/intel-rapl:0/energy_uj", "1000000\n")
	write(t, root, "sys/class/powercap/intel-rapl:0/max_energy_range_uj", "10000000\n")
	return root
}

func TestRead(t *testing.T) {
	root := fakeHost(t)
	r := &Reader{Root: root, CacheFor: 0, BaseW: 40, PriceKWh: 1.3}
	if !r.Found() {
		t.Fatal("not found")
	}
	d := r.Read()
	// busy = (1000 - 800) / 1000 since boot
	want := map[string]any{"cpu": 20.0, "mem": 60.0, "load1": 0.42, "uptime": int64(3600), "cpu_temp": 48.3, "gpu_count": 0}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("%s = %#v, want %#v", k, d[k], v)
		}
	}
	if m := d["mem_used_of"].([]int64); m[0] != 600*1024 || m[1] != 1000*1024 {
		t.Errorf("mem_used_of %v", m)
	}
	if _, ok := d["disk"]; !ok {
		t.Error("no disk")
	}
	if _, ok := d["power"]; ok {
		t.Error("power on the first RAPL sample")
	}
	// second sample: 200 more ticks, 50 idle
	write(t, root, "proc/stat", "cpu  200 0 150 750 100 0 0 0 0 0\n")
	r.raplT = r.raplT.Add(-2 * time.Second) // as if two seconds passed
	write(t, root, "sys/class/powercap/intel-rapl:0/energy_uj", "21000000\n")
	r.raplE = 1000000
	d = r.Read()
	if d["cpu"] != 75.0 {
		t.Errorf("cpu %v, want 75", d["cpu"])
	}
	if d["power_cpu"] != 10.0 || d["power"] != 50.0 || d["power_base"] != 40.0 || d["kwh_day"] != 1.2 || d["cost_day"] != 1.56 {
		t.Errorf("power %v %v %v %v %v", d["power_cpu"], d["power"], d["power_base"], d["kwh_day"], d["cost_day"])
	}
	// a sample too soon keeps the last numbers
	d = r.Read()
	if d["power"] != 50.0 {
		t.Errorf("power not kept: %v", d["power"])
	}
}

func TestRAPLWrap(t *testing.T) {
	root := fakeHost(t)
	r := &Reader{Root: root, raplOK: true, raplE: 9000000, raplT: time.Now().Add(-time.Second)}
	out := map[string]any{}
	r.power(out, 0) // 1000000 + 10000000 - 9000000 = 2 J in 1 s
	if v, _ := out["power_cpu"].(float64); v < 1.9 || v > 2.0 {
		t.Errorf("power_cpu %v after a wrap", out["power_cpu"])
	}
}

func TestGPUs(t *testing.T) {
	out := map[string]any{}
	w := parseGPUs("0, 41, 3, 1024, 8192, 9.50\n1, 55, 97, 4096, 16384, [N/A]\nbroken\n", out)
	if out["gpu_count"] != 2 || w != 9.5 {
		t.Fatalf("count %v watts %v", out["gpu_count"], w)
	}
	if out["gpu0_mem"] != 12.5 || out["gpu1_util"] != 97.0 || out["gpu1_mem_total_mib"] != 16384.0 {
		t.Errorf("%v", out)
	}
	if _, ok := out["gpu1_power"]; ok {
		t.Error("power for [N/A]")
	}
}

func TestCacheCopies(t *testing.T) {
	r := &Reader{Root: fakeHost(t), CacheFor: time.Minute}
	a := r.Read()
	a["cpu"] = "changed"
	if r.Read()["cpu"] == "changed" {
		t.Error("Read gave the cache itself")
	}
}

func TestNetwork(t *testing.T) {
	root := t.TempDir()
	dev := func(eth0rx, eth0tx int) string {
		return "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes\n" +
			"    lo: 9999 1 0 0 0 0 0 0 9999 1 0 0 0 0 0 0\n" +
			fmt.Sprintf("  eth0: %d 10 0 0 0 0 0 0 %d 10 0 0 0 0 0 0\n", eth0rx, eth0tx) +
			"veth1: 5000 1 0 0 0 0 0 0 5000 1 0 0 0 0 0 0\n"
	}
	write(t, root, "proc/net/dev", dev(1000, 500))
	r := &Reader{Root: root}
	out := map[string]any{}
	r.network(out)
	if _, ok := out["net_rx"]; ok {
		t.Fatal("a rate from one read")
	}
	r.netT = r.netT.Add(-2 * time.Second)
	write(t, root, "proc/net/dev", dev(5000, 2500))
	r.network(out)
	if rx, tx := out["net_rx"].(int64), out["net_tx"].(int64); rx < 1990 || rx > 2000 || tx < 995 || tx > 1000 {
		t.Errorf("no /sys: lo and veth left out, got %v", out)
	}
	// with /sys saying which card is physical, only that one counts
	write(t, root, "sys/class/net/veth1/device/x", "")
	r.netT = r.netT.Add(-1 * time.Second)
	r.network(out)
	if out["net_rx"].(int64) != 0 {
		t.Errorf("only veth1 counts now and it did not move: %v", out)
	}
}
