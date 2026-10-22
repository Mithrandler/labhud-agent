package allow

import "testing"

func TestDockerKinds(t *testing.T) {
	l := &List{}
	l.caps = []string{"docker"}
	l.targets = map[string][]string{"docker": {"web", "images", "volume:pgdata"}}
	cases := []struct {
		verb, target string
		ok           bool
	}{
		{"restart", "web", true},
		{"restart", "images", false},
		{"restart", "volume:pgdata", false},
		{"rm-image", "images", true},
		{"rm-volume", "images", true},
		{"rm-network", "images", true},
		{"pull", "images", true},
		{"network-inspect", "images", true},
		{"rm-image", "web", false}, // a host verb on a container
		{"pull", "web", false},
		{"volume-ls", "volume:pgdata", true},
		{"volume-read", "volume:pgdata", true},
		{"volume-ls", "web", false},          // a volume verb on a container
		{"volume-ls", "images", false},       // or on the host's Docker
		{"volume-ls", "volume:other", false}, // a volume that is not ticked
		{"stats", "volume:pgdata", false},
		{"logs", "volume:pgdata", false},
		{"prune", "volume:pgdata", false},
	}
	for _, c := range cases {
		err := l.Check("docker", c.verb, c.target)
		if (err == nil) != c.ok {
			t.Errorf("%s on %s: allowed=%v, want %v", c.verb, c.target, err == nil, c.ok)
		}
	}
}

func TestCheckArg(t *testing.T) {
	ok := []struct{ verb, arg string }{
		{"rm-image", "nginx:1.27"}, {"rm-image", "0a1b2c3d4e5f"}, {"rm-image", "ghcr.io/org/app@sha256:abc"},
		{"pull", "jellyfin/jellyfin:10.10"},
		{"rm-network", "media_default"}, {"rm-volume", "pgdata"}, {"network-inspect", "proxy"},
		{"volume-ls", ""}, {"volume-ls", "/"}, {"volume-ls", "/base/16384"}, {"volume-read", "/postgresql.conf"},
		{"volume-read", "/dir with spaces/file.txt"},
		{"version", "1760000000"}, {"restore", "1"}, {"restore", "999999999999"},
		{"restart", ""}, {"logs", ""},
	}
	for _, c := range ok {
		if err := CheckArg(c.verb, c.arg); err != nil {
			t.Errorf("%s %q refused: %v", c.verb, c.arg, err)
		}
	}
	bad := []struct{ verb, arg string }{
		{"rm-image", ""}, {"rm-image", "-f"}, {"rm-image", "a b"}, {"rm-image", "x;rm -rf /"}, {"rm-image", "a\nb"},
		{"pull", ""}, {"pull", "../x"},
		{"rm-network", "a/b"}, {"rm-volume", "../etc"}, {"rm-volume", ""}, {"network-inspect", "-all"},
		{"volume-ls", "/../etc"}, {"volume-ls", "/a/../../b"}, {"volume-ls", "/a\x00b"}, {"volume-ls", "/a\nb"},
		{"volume-read", ""}, {"volume-read", "/"}, {"volume-read", "/x/../../etc/passwd"},
		{"version", ""}, {"restore", ""}, {"version", "-1"}, {"restore", "../1"}, {"version", "1.5"}, {"restore", "1 2"},
		{"version", "1234567890123"}, {"restore", "1;rm"}, {"version", "\n1"}, {"restore", "latest"},
		{"restart", "x"}, {"logs", "x"}, {"stats", "--all"}, {"inventory", "x"}, {"prune", "x"}, {"start", "../"},
	}
	for _, c := range bad {
		if err := CheckArg(c.verb, c.arg); err == nil {
			t.Errorf("%s %q was accepted", c.verb, c.arg)
		}
	}
	long := "/" + string(make([]byte, 0))
	for i := 0; i < MaxPath+1; i++ {
		long += "a"
	}
	if CheckArg("volume-ls", long) == nil {
		t.Error("a path over the limit was accepted")
	}
}

func TestCleanPath(t *testing.T) {
	for in, want := range map[string]string{"": "/", "/": "/", "a": "/a", "/a//b/": "/a/b", "/a/./b": "/a/b"} {
		got, err := CleanPath(in)
		if err != nil || got != want {
			t.Errorf("CleanPath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}
