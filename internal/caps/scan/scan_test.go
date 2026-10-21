package scan

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/allow"
	"github.com/Mithrandler/labhud-agent/internal/proto"
)

var idA = "sha256:" + strings.Repeat("a", 64)
var idB = "sha256:" + strings.Repeat("b", 64)

const trivySample = `{"SchemaVersion":2,"ArtifactName":"x","Results":[{"Target":"debian","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"openssl","Severity":"CRITICAL"},{"VulnerabilityID":"CVE-1","PkgName":"openssl","Severity":"CRITICAL"},{"VulnerabilityID":"CVE-1","PkgName":"libssl3","Severity":"CRITICAL"},{"VulnerabilityID":"CVE-2","PkgName":"zlib","Severity":"HIGH"},{"VulnerabilityID":"CVE-3","PkgName":"curl","Severity":"MEDIUM"}]},{"Target":"app","Vulnerabilities":null}]}`

const grypeSample = `{"matches":[{"vulnerability":{"id":"CVE-9","severity":"Critical"},"artifact":{"name":"glibc"}},{"vulnerability":{"id":"CVE-8","severity":"High"},"artifact":{"name":"bash"}},{"vulnerability":{"id":"CVE-8","severity":"High"},"artifact":{"name":"bash"}},{"vulnerability":{"id":"CVE-7","severity":"Low"},"artifact":{"name":"tar"}}]}`

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func fake(t *testing.T, out string, calls *int) func(ctx context.Context, path string, args ...string) (io.ReadCloser, func() error, error) {
	t.Helper()
	return func(ctx context.Context, path string, args ...string) (io.ReadCloser, func() error, error) {
		*calls++
		return io.NopCloser(strings.NewReader(out)), func() error { return nil }, nil
	}
}

func TestParseTrivy(t *testing.T) {
	sum, err := ParseTrivy(strings.NewReader(trivySample))
	if err != nil {
		t.Fatalf("ParseTrivy(sample) error: %v", err)
	}
	if sum.Critical != 2 {
		t.Errorf("Critical = %d, want 2", sum.Critical)
	}
	if sum.High != 1 {
		t.Errorf("High = %d, want 1", sum.High)
	}

	sum, err = ParseTrivy(strings.NewReader(`{"SchemaVersion":2}`))
	if err != nil {
		t.Fatalf("ParseTrivy(empty results) error: %v", err)
	}
	if sum.Critical != 0 || sum.High != 0 {
		t.Errorf("got Critical=%d High=%d, want 0 0", sum.Critical, sum.High)
	}

	if _, err := ParseTrivy(strings.NewReader(`{}`)); err == nil {
		t.Error("ParseTrivy({}) expected error, got nil")
	}
	if _, err := ParseTrivy(strings.NewReader("not json")); err == nil {
		t.Error("ParseTrivy(not json) expected error, got nil")
	}
}

func TestParseGrype(t *testing.T) {
	sum, err := ParseGrype(strings.NewReader(grypeSample))
	if err != nil {
		t.Fatalf("ParseGrype(sample) error: %v", err)
	}
	if sum.Critical != 1 {
		t.Errorf("Critical = %d, want 1", sum.Critical)
	}
	if sum.High != 1 {
		t.Errorf("High = %d, want 1", sum.High)
	}

	sum, err = ParseGrype(strings.NewReader(`{"matches":[]}`))
	if err != nil {
		t.Fatalf("ParseGrype(empty matches) error: %v", err)
	}
	if sum.Critical != 0 || sum.High != 0 {
		t.Errorf("got Critical=%d High=%d, want 0 0", sum.Critical, sum.High)
	}

	if _, err := ParseGrype(strings.NewReader(`{}`)); err == nil {
		t.Error("ParseGrype({}) expected error, got nil")
	}
	if _, err := ParseGrype(strings.NewReader("[")); err == nil {
		t.Error("ParseGrype([) expected error, got nil")
	}
}

func TestArgs(t *testing.T) {
	got := Args("trivy", idA)
	want := []string{"image", "--quiet", "--format", "json", "--scanners", "vuln", "--timeout", "15m", idA}
	if !equal(got, want) {
		t.Errorf("Args(trivy) = %v, want %v", got, want)
	}

	got = Args("grype", idA)
	want = []string{"docker:" + idA, "-o", "json", "-q"}
	if !equal(got, want) {
		t.Errorf("Args(grype) = %v, want %v", got, want)
	}
}

func TestImageCachesAndRescans(t *testing.T) {
	s := &Scanner{Tool: "trivy", Path: "/usr/bin/trivy"}
	var calls int
	s.run = fake(t, trivySample, &calls)
	now := time.Unix(1760000000, 0)
	s.now = func() time.Time { return now }

	ctx := context.Background()

	sum, err := s.Image(ctx, idA)
	if err != nil {
		t.Fatalf("first Image: %v", err)
	}
	if sum.Critical != 2 {
		t.Errorf("first Image Critical = %d, want 2", sum.Critical)
	}
	if sum.Tool != "trivy" {
		t.Errorf("first Image Tool = %q, want trivy", sum.Tool)
	}
	if sum.T != 1760000000 {
		t.Errorf("first Image T = %d, want 1760000000", sum.T)
	}
	if calls != 1 {
		t.Fatalf("calls after first Image = %d, want 1", calls)
	}

	sum, err = s.Image(ctx, idA)
	if err != nil {
		t.Fatalf("second Image: %v", err)
	}
	if sum.Critical != 2 {
		t.Errorf("second Image Critical = %d, want 2", sum.Critical)
	}
	if sum.T != 1760000000 {
		t.Errorf("second Image T = %d, want 1760000000 (cached)", sum.T)
	}
	if calls != 1 {
		t.Fatalf("calls after second Image = %d, want 1 (cached)", calls)
	}

	now = now.Add(Fresh + time.Minute)
	_, err = s.Image(ctx, idA)
	if err != nil {
		t.Fatalf("third Image (stale): %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls after stale Image = %d, want 2", calls)
	}

	if _, err := s.Image(ctx, "nginx:latest"); err == nil {
		t.Error("Image(nginx:latest) expected error, got nil")
	}
	if calls != 2 {
		t.Errorf("calls after bad id = %d, want 2", calls)
	}
}

func TestImageScannerFails(t *testing.T) {
	s := &Scanner{Tool: "trivy", Path: "/usr/bin/trivy"}
	var calls int
	s.run = func(ctx context.Context, path string, args ...string) (io.ReadCloser, func() error, error) {
		calls++
		return io.NopCloser(strings.NewReader(trivySample)), func() error { return errors.New("exit status 1") }, nil
	}
	now := time.Unix(1760000000, 0)
	s.now = func() time.Time { return now }

	ctx := context.Background()

	if _, err := s.Image(ctx, idA); err == nil {
		t.Fatal("Image with failing wait: expected error, got nil")
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}

	if _, err := s.Image(ctx, idA); err == nil {
		t.Fatal("Image (retry after failure): expected error, got nil")
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2 (not cached)", calls)
	}

	// garbage output, wait succeeds → parse error
	s2 := &Scanner{Tool: "trivy", Path: "/usr/bin/trivy"}
	var calls2 int
	s2.run = func(ctx context.Context, path string, args ...string) (io.ReadCloser, func() error, error) {
		calls2++
		return io.NopCloser(strings.NewReader("garbage")), func() error { return nil }, nil
	}
	s2.now = func() time.Time { return now }
	if _, err := s2.Image(ctx, idB); err == nil {
		t.Fatal("Image with garbage output: expected error, got nil")
	}
	if calls2 != 1 {
		t.Fatalf("calls2 = %d, want 1", calls2)
	}
}

func TestRoundAndFill(t *testing.T) {
	a := &allow.List{}
	a.Set(proto.Allow{Caps: []string{"docker", "scan"}, Targets: map[string][]string{"docker": {"web", "db", "images"}}})
	s := &Scanner{Tool: "grype", Path: "/usr/bin/grype", Allow: a}
	var calls int
	s.run = fake(t, grypeSample, &calls)
	s.ImageOf = func(ctx context.Context, name string) (string, error) {
		if name == "images" {
			t.Errorf("ImageOf called with prune target %q", name)
			return "", errors.New("should not be called")
		}
		switch name {
		case "web", "db":
			return idA, nil
		}
		return "", errors.New("no such container")
	}

	s.Round(context.Background())
	if calls != 1 {
		t.Fatalf("calls after Round = %d, want 1 (same image scanned once)", calls)
	}

	st := proto.State{Containers: map[string]map[string]any{
		"web":   {"state": "running"},
		"db":    {},
		"other": {},
	}}
	s.Fill(context.Background(), &st)

	webScan, ok := st.Containers["web"]["scan"].(map[string]any)
	if !ok {
		t.Fatal("st.Containers[web][scan] missing or wrong type")
	}
	if webScan["critical"] != 1 {
		t.Errorf("web scan critical = %v, want 1", webScan["critical"])
	}
	if webScan["high"] != 1 {
		t.Errorf("web scan high = %v, want 1", webScan["high"])
	}
	if webScan["tool"] != "grype" {
		t.Errorf("web scan tool = %v, want grype", webScan["tool"])
	}

	dbScan, ok := st.Containers["db"]["scan"].(map[string]any)
	if !ok {
		t.Fatal("st.Containers[db][scan] missing or wrong type")
	}
	if dbScan["critical"] != 1 {
		t.Errorf("db scan critical = %v, want 1", dbScan["critical"])
	}
	if dbScan["high"] != 1 {
		t.Errorf("db scan high = %v, want 1", dbScan["high"])
	}

	if _, has := st.Containers["other"]["scan"]; has {
		t.Error("st.Containers[other] should not have scan key")
	}
}

func TestNothingWhenNotTicked(t *testing.T) {
	a := &allow.List{}
	a.Set(proto.Allow{Caps: []string{"docker"}, Targets: map[string][]string{"docker": {"web", "db"}}})
	s := &Scanner{Tool: "grype", Path: "/usr/bin/grype", Allow: a}
	var calls int
	s.run = fake(t, grypeSample, &calls)
	s.ImageOf = func(ctx context.Context, name string) (string, error) {
		return idA, nil
	}

	s.Round(context.Background())
	if calls != 0 {
		t.Fatalf("calls after Round = %d, want 0 (scan not ticked)", calls)
	}

	st := proto.State{Containers: map[string]map[string]any{
		"web": {"state": "running"},
	}}
	s.Fill(context.Background(), &st)
	if _, has := st.Containers["web"]["scan"]; has {
		t.Error("st.Containers[web] should not have scan key when scan not ticked")
	}
}
