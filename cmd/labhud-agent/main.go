// labhud-agent: one per host, dials labhud and acts only through the host's local APIs, only
// on what the admin ticked in labhud's ⚙ > Agents. See README.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Mithrandler/labhud-agent/internal/allow"
	"github.com/Mithrandler/labhud-agent/internal/caps"
	"github.com/Mithrandler/labhud-agent/internal/caps/docker"
	"github.com/Mithrandler/labhud-agent/internal/caps/ptero"
	"github.com/Mithrandler/labhud-agent/internal/caps/pve"
	"github.com/Mithrandler/labhud-agent/internal/caps/scan"
	"github.com/Mithrandler/labhud-agent/internal/caps/sensors"
	"github.com/Mithrandler/labhud-agent/internal/caps/stacks"
	"github.com/Mithrandler/labhud-agent/internal/caps/systemd"
	"github.com/Mithrandler/labhud-agent/internal/caps/wol"
	"github.com/Mithrandler/labhud-agent/internal/config"
	"github.com/Mithrandler/labhud-agent/internal/conn"
	"github.com/Mithrandler/labhud-agent/internal/selfupdate"
)

var version = "dev" // set at build: -ldflags "-X main.version=0.1.0"

func main() {
	dir := flag.String("dir", config.DefaultDir, "settings and key folder (LABHUD_AGENT_DIR)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	logger := log.New(os.Stderr, "", 0) // journald and docker logs add the time
	cfg, err := config.Load(*dir)
	if err != nil {
		logger.Fatalf("settings: %v", err)
	}
	if cfg.URL == "" {
		logger.Fatalf("LABHUD_URL is not set (in %s/config or the environment)", cfg.Dir)
	}
	agent := &conn.Agent{Cfg: cfg, Version: version, Log: logger, Allow: &allow.List{},
		Update: &selfupdate.Updater{Own: version, Releases: cfg.Releases, InContainer: cfg.InContainer()}}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	agent.Caps = detect(ctx, cfg, agent, logger)
	logger.Printf("labhud-agent %s, labhud at %s", version, cfg.URL)
	err = agent.Run(ctx)
	switch {
	case errors.Is(err, conn.ErrRemoved):
		logger.Print(err)
		os.Exit(0) // the unit has Restart=on-failure: it stays stopped
	case errors.Is(err, conn.ErrPairing):
		logger.Print(err)
		os.Exit(2) // RestartPreventExitStatus=2
	case ctx.Err() != nil:
		logger.Print("stopped")
	default:
		logger.Fatal(err)
	}
}

// detect finds what this host has; each capability reports itself in hello.
func detect(ctx context.Context, cfg config.Config, agent *conn.Agent, logger *log.Logger) []caps.Cap {
	var found []caps.Cap
	if s := sensors.New(cfg.Root, cfg.BaseW, cfg.PriceKWh); s.Found() {
		found = append(found, s)
	}
	if d := docker.New(docker.Socket); d != nil {
		d.Allow, d.Send, d.AutoLabels = agent.Allow, agent.Send, cfg.AutoLabels
		go d.Watch(ctx)
		go d.Events(ctx)
		go d.Measure(ctx)
		found = append(found, d)
		if cfg.Terminal {
			found = append(found, &docker.Terminal{D: d})
		}
		// scan: trivy or grype on the host; after docker, so its Fill sees the containers
		if s := scan.New(agent.Allow, d.ImageOf); s != nil {
			s.Log = logger.Printf
			d.Scan = func(ctx context.Context, id string) (int, error) {
				sum, err := s.Image(ctx, id)
				return sum.Critical, err
			}
			go s.Watch(ctx)
			found = append(found, s)
		}
	}
	if bus := systemd.Connect(ctx); bus != nil {
		found = append(found, &systemd.Units{Bus: bus, Allow: agent.Allow},
			systemd.NewHost(bus, cfg.Root, agent.Emit))
	} else {
		logger.Print("no D-Bus: no systemd or host capability (mount /run/dbus in a container)")
	}
	if cfg.Stacks != "" {
		if st := stacks.New(cfg.Stacks, nil); st != nil {
			found = append(found, st)
		} else {
			logger.Print("LABHUD_AGENT_STACKS is set but there is no `docker compose` here (or the folder is not writable): no stacks")
		}
	}
	found = append(found, wol.New(cfg.Root))
	if p := pve.New(cfg.PVEURL, cfg.PVEToken, cfg.Root); p != nil {
		peers, err := pve.ParsePeers(cfg.PVEPeers)
		if err != nil {
			logger.Printf("LABHUD_PVE_PEERS: %v (no migration)", err)
		}
		p.Peers = peers
		found = append(found, p)
	}
	if p := ptero.New(cfg.PteroURL, cfg.PteroKey, cfg.PteroPin); p != nil {
		found = append(found, p)
	}
	names := make([]string, 0, len(found))
	for _, c := range found {
		names = append(names, c.Name())
	}
	logger.Printf("found: %v", names)
	return found
}
