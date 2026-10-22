package systemd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const sample = `Reading package lists...
Inst libssl3 [3.0.1] (3.0.2 Debian-Security:13/stable-security [amd64])
Inst curl [8.1] (8.2 Debian:13.1/stable [amd64])
Conf curl (8.2 Debian:13.1/stable [amd64])
`

func TestParseInst(t *testing.T) {
	u := ParseInst(sample)
	if u["pending"] != 2 || u["security"] != 1 || u["names"].([]string)[0] != "libssl3" {
		t.Errorf("got %v", u)
	}
	if ParseInst("nothing\n")["pending"] != 0 {
		t.Error("nothing pending")
	}
}

func TestPendingCachedAndHostOnly(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755)
	os.WriteFile(filepath.Join(root, "usr/bin/apt-get"), nil, 0o755)
	calls := 0
	h := &Host{Root: root, Simulate: func(context.Context) (string, error) { calls++; return sample, nil }}
	if h.pending(context.Background()) != nil {
		t.Error("a root that is not / is a container: no count")
	}
	h.Root = "/"
	if !h.exists("usr/bin/apt-get") {
		t.Skip("no apt-get on this machine")
	}
	a, b := h.pending(context.Background()), h.pending(context.Background())
	if a["pending"] != 2 || b["pending"] != 2 || calls != 1 {
		t.Errorf("pending %v %v after %d runs", a, b, calls)
	}
}
