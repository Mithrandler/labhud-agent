package conn

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrimaryMAC(t *testing.T) {
	root := t.TempDir()
	put := func(p, s string) {
		t.Helper()
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got := primaryMAC(root); got != "" {
		t.Errorf("nothing to read: %q", got)
	}
	put("proc/net/route", "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"+
		"wlo1\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"+
		"vmbr0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"+
		"vmbr0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n")
	put("sys/class/net/vmbr0/address", "02:00:00:00:00:7B\n")
	put("sys/class/net/wlo1/address", "e0:8f:4c:37:0a:4b\n")
	if got := primaryMAC(root); got != "02:00:00:00:00:7b" {
		t.Errorf("the route of lowest metric: %q", got)
	}
	put("sys/class/net/vmbr0/address", "00:00:00:00:00:00\n")
	if got := primaryMAC(root); got != "" {
		t.Errorf("a zero address is none: %q", got)
	}
}
