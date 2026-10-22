// Package caps is what the agent can do on its host. Each capability finds itself at start
// (a socket, D-Bus, an API, a key) and is reported in `hello`; labhud decides which are used.
package caps

import (
	"context"
	"errors"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/proto"
)

type Cap interface {
	Name() string
	// Fill adds this capability's part of the state. Read-only, called every few seconds.
	Fill(ctx context.Context, st *proto.State)
	// Do carries out one verb on one target. The allowlist was checked before.
	Do(ctx context.Context, verb, target string) error
}

// Reader is a capability with verbs that read instead of act (docker logs): their answer goes
// back in the result's output.
type Reader interface {
	Read(ctx context.Context, verb, target string) (string, error)
	Reads(verb string) bool
}

// ArgRunner is a capability whose verbs take an argument (docker rm-image, volume-ls): the answer is
// the output, as a Reader's. The argument has been checked by allow.CheckArg before this.
type ArgRunner interface {
	TakesArg(verb string) bool
	RunArg(ctx context.Context, verb, target, arg string) (string, error)
}

// MaxOutput bounds what a read verb sends back (a frame stays well under labhud's limit).
const MaxOutput = 48 << 10

// ErrNoVerb: a capability that only reports (sensors), or a verb it does not know.
var ErrNoVerb = errors.New("this capability has no such action")

// UpdateOptions is what a command adds to an update: a registry's login (opened from its seal,
// for that registry only) and whether a new image with more critical CVEs is held back.
type UpdateOptions struct {
	Registry     string
	Login        *proto.Login
	HoldCritical bool
}

// Updater is a capability whose update takes UpdateOptions (docker).
type Updater interface {
	UpdateWith(target string, opt UpdateOptions) error
}

// Slow is a capability whose verbs take longer than a command usually may (a compose pull).
type Slow interface {
	Timeout(verb string) time.Duration
}

// Deployer is a capability that takes files with a verb (stacks: deploy): the answer is the
// output, as a Reader's.
type Deployer interface {
	Deploy(ctx context.Context, verb, target string, files map[string]string) (string, error)
}

// Stream is something open on the host that output comes out of and input may go into: a
// container's log being followed (input is refused), a shell in a container.
type Stream interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Resize(cols, rows int) error
	Close() error
}

// Streamer is a capability with verbs that open a Stream. The allow list was checked before.
type Streamer interface {
	Streams(verb string) bool
	// Limits: the longest a stream of this verb lives and how long it may sit without input
	// (0: no idle limit)
	Limits(verb string) (life, idle time.Duration)
	Open(ctx context.Context, verb, target string, cols, rows int) (Stream, error)
}
