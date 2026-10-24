package conn

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// primaryMAC is the hardware address of the card the default route leaves by: what a Wake of this
// machine is sent to. "" when there is none to read (no route, or no /sys: a container without it).
func primaryMAC(root string) string {
	b, err := os.ReadFile(filepath.Join(root, "proc/net/route"))
	if err != nil {
		return ""
	}
	best, bestMetric := "", -1
	for i, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 7 || f[1] != "00000000" {
			continue
		}
		metric, err := strconv.Atoi(f[6])
		if err != nil {
			continue
		}
		if bestMetric < 0 || metric < bestMetric {
			best, bestMetric = f[0], metric
		}
	}
	if best == "" || strings.ContainsAny(best, "/.") {
		return ""
	}
	a, err := os.ReadFile(filepath.Join(root, "sys/class/net", best, "address"))
	if err != nil {
		return ""
	}
	hw, err := net.ParseMAC(strings.TrimSpace(string(a)))
	if err != nil || len(hw) != 6 || hw.String() == "00:00:00:00:00:00" {
		return ""
	}
	return hw.String()
}
