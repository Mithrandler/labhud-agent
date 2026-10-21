package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		v, own string
		want   bool
	}{
		{"0.1.1", "0.1.0", true},
		{"0.1.0", "0.1.0", false},
		{"0.1.0", "0.1.1", false},
		{"0.1.0", "0.1.0-dev.a0e2b4d", true},
		{"0.1.0", "dev", true},
		{"1.0.0", "0.9.99", true},
		{"0.1.0-rc1", "0.0.1", false}, // labhud only ever names a release
		{"x", "0.1.0", false},
	} {
		if got := Newer(c.v, c.own); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.v, c.own, got)
		}
	}
}

func TestSumFor(t *testing.T) {
	sums := "aa" + strings.Repeat("0", 62) + "  labhud-agent-linux-amd64\n" + strings.Repeat("B", 64) + " *labhud-agent-linux-arm64\n"
	if got := sumFor(sums, "labhud-agent-linux-amd64"); got != "aa"+strings.Repeat("0", 62) {
		t.Fatal(got)
	}
	if got := sumFor(sums, "labhud-agent-linux-arm64"); got != strings.Repeat("b", 64) {
		t.Fatal(got)
	}
	if sumFor(sums, "labhud-agent-linux-riscv64") != "" {
		t.Fatal("found a build that is not there")
	}
}

// a release server with one build, and the running binary in a temporary folder
func setup(t *testing.T, bin []byte, sumsOverride string) (*Updater, string, string) {
	t.Helper()
	sum := sha256.Sum256(bin)
	want := hex.EncodeToString(sum[:])
	sums := want + "  " + Asset() + "\n"
	if sumsOverride != "" {
		sums = sumsOverride
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v0.1.0/SHA256SUMS":
			w.Write([]byte(sums))
		case "/v0.1.0/" + Asset():
			w.Write(bin)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	exe := filepath.Join(t.TempDir(), "labhud-agent")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &Updater{Own: "0.0.1", Releases: srv.URL, Exe: exe, Client: srv.Client()}, exe, want
}

func TestFetchReplaces(t *testing.T) {
	u, exe, want := setup(t, []byte("new binary"), "")
	got, err := u.Fetch(context.Background(), "0.1.0", want)
	if err != nil || got != exe {
		t.Fatal(got, err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "new binary" {
		t.Fatalf("binary is %q", b)
	}
	if fi, _ := os.Stat(exe); fi.Mode().Perm() != 0o755 {
		t.Fatal(fi.Mode())
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), ".labhud-agent-*")); len(left) != 0 {
		t.Fatal("a temporary file was left:", left)
	}
}

func TestFetchRefuses(t *testing.T) {
	u, exe, want := setup(t, []byte("new binary"), "")
	other := strings.Repeat("1", 64)
	for name, run := range map[string]func() error{
		"labhud's sum is not the release's": func() error { _, err := u.Fetch(context.Background(), "0.1.0", other); return err },
		"not newer":                         func() error { _, err := u.Fetch(context.Background(), "0.0.1", want); return err },
		"no such release": func() error {
			_, err := (&Updater{Own: "0.0.1", Releases: u.Releases, Exe: exe, Client: u.Client}).Fetch(context.Background(), "0.1.1", want)
			return err
		},
		"in a container": func() error {
			_, err := (&Updater{Own: "0.0.1", Releases: u.Releases, Exe: exe, Client: u.Client, InContainer: true}).Fetch(context.Background(), "0.1.0", want)
			return err
		},
		"plain http": func() error {
			_, err := (&Updater{Own: "0.0.1", Releases: "http://example.org", Exe: exe}).Fetch(context.Background(), "0.1.0", want)
			return err
		},
		"not a version": func() error { _, err := u.Fetch(context.Background(), "../../x", want); return err },
	} {
		if run() == nil {
			t.Errorf("%s: updated", name)
		}
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatalf("binary replaced: %q", b)
	}
}

func TestFetchRefusesATamperedDownload(t *testing.T) {
	// SHA256SUMS and labhud agree, the file served is something else
	listed := strings.Repeat("2", 64)
	u, exe, _ := setup(t, []byte("tampered"), listed+"  "+Asset()+"\n")
	if _, err := u.Fetch(context.Background(), "0.1.0", listed); err == nil {
		t.Fatal("updated")
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatalf("binary replaced: %q", b)
	}
}
