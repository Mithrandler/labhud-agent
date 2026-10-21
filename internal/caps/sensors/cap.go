package sensors

import (
	"context"

	"github.com/Mithrandler/labhud-agent/internal/caps"
	"github.com/Mithrandler/labhud-agent/internal/proto"
)

func (r *Reader) Name() string { return "sensors" }

func (r *Reader) Fill(_ context.Context, st *proto.State) { st.Sensors = r.Read() }

func (r *Reader) Do(context.Context, string, string) error { return caps.ErrNoVerb }
