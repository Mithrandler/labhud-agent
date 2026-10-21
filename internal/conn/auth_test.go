package conn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/caps"
	"github.com/Mithrandler/labhud-agent/internal/proto"
)

// updCap is a docker capability with UpdateWith: it keeps what each update was given.
type updCap struct {
	fakeCap
	mu   sync.Mutex
	opts []caps.UpdateOptions
}

func (c *updCap) UpdateWith(target string, opt caps.UpdateOptions) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.opts = append(c.opts, opt)
	return nil
}

// A sealed registry login in an update command is opened with the agent's key, for that command
// of that connection only; a box that does not open fails the command without updating.
func TestSealedLogin(t *testing.T) {
	c := &updCap{}
	results := make(chan proto.Result, 4)
	var hello proto.Hello
	f := &fakeLabhud{t: t, allow: proto.Allow{Caps: []string{"docker"}, Targets: map[string][]string{"docker": {"web"}}}}
	f.script = func(s *srvSession) {
		nonce := strings.Repeat("0f", 16)
		seal := func(cmd, text string) *proto.SealedAuth {
			box, _ := proto.Seal(s.key, s.sid, cmd, nonce, text)
			return &proto.SealedAuth{Registry: "ghcr.io", Nonce: nonce, Box: box}
		}
		login := `{"username":"demo","password":"tok"}`
		other, _ := proto.Seal(s.key, s.sid, strings.Repeat("9", 16), nonce, login) // sealed for another command
		for i, cmd := range []proto.Command{
			{Cap: "docker", Verb: "update", Target: "web", Cmd: strings.Repeat("1", 16), HoldCritical: true},
			{Cap: "docker", Verb: "update", Target: "web", Cmd: strings.Repeat("2", 16)},
			{Cap: "docker", Verb: "update", Target: "web", Cmd: strings.Repeat("3", 16),
				Auth: &proto.SealedAuth{Registry: "ghcr.io", Nonce: nonce, Box: other}},
			{Cap: "docker", Verb: "update", Target: "web", Cmd: strings.Repeat("4", 16)},
		} {
			cmd.Type = "command"
			if i == 1 {
				cmd.Auth = seal(cmd.Cmd, login)
			}
			s.send(cmd)
			fr, err := s.read()
			if err != nil {
				t.Errorf("reading a result: %v", err)
				return
			}
			var r proto.Result
			json.Unmarshal(fr.Body, &r)
			results <- r
		}
		s.send(proto.Bye{Type: "bye", Reason: "removed"})
		time.Sleep(200 * time.Millisecond)
	}
	srv := httptest.NewServer(f)
	defer srv.Close()
	a := newAgent(t, srv.URL, c)
	hello = a.hello()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.Run(ctx); !errors.Is(err, ErrRemoved) {
		t.Fatalf("Run: %v", err)
	}
	if !slices.Contains(hello.Features, "registry-auth") {
		t.Errorf("hello features %v", hello.Features)
	}
	for i, want := range []string{"", "", "the registry login does not open", ""} {
		r := <-results
		if r.OK != (want == "") || r.Error != want {
			t.Errorf("command %d: %+v", i, r)
		}
	}
	if len(c.opts) != 2 || !c.opts[0].HoldCritical || c.opts[0].Login != nil {
		t.Fatalf("UpdateWith got %+v", c.opts)
	}
	if l := c.opts[1].Login; l == nil || l.Username != "demo" || l.Password != "tok" || c.opts[1].Registry != "ghcr.io" {
		t.Errorf("login %+v", c.opts[1])
	}
	// a plain update (no auth, no hold) is the capability's Do, as for an older labhud
	if strings.Join(c.done, ",") != "update web" {
		t.Errorf("Do got %v", c.done)
	}
}
