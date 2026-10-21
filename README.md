# labhud-agent

One small agent per host for [labhud](https://github.com/Mithrandler/labhud). It dials labhud
(nothing listens on the host), reports the host's sensors and what it runs, and carries out the
actions the admin ticked in labhud's ⚙ > Agents — only through the host's own APIs, never a shell.

| capability | found when | labhud can |
|---|---|---|
| `sensors` | always (Linux) | read CPU, memory, disk, load, uptime, CPU temperature, NVIDIA GPUs, RAPL power |
| `docker` | `/var/run/docker.sock` exists | start, stop, restart containers |
| `systemd` | D-Bus is reachable | start, stop, restart units |
| `host` | D-Bus is reachable | reboot, shut down, update packages |
| `wol` | always | wake other machines on the LAN |
| `pve` | a Proxmox token is set (`LABHUD_PVE_TOKEN`) | start, shut down, reboot VMs and LXCs |
| `ptero` | a Pterodactyl client key is set (`LABHUD_PTERO_URL`, `LABHUD_PTERO_KEY`; `LABHUD_PTERO_PIN` for a self-signed panel) | start, stop, restart game servers |

Every capability is **off until ticked** in labhud, and so is every target (each container, VM,
unit, server). The agent checks the same allowlist itself before it touches anything.

## Installing

On the host, as root, with a one-time code from labhud's ⚙ > Agents > **Add an agent** (the
admin signed in). ⚙ shows the exact command; there are two, depending on the labhud:

- **labhud pins a release of this agent** (its `agents/agent-release.json`, filled in when labhud
  is released). Its installer downloads the build for the host's architecture from this repo's
  releases and checks it against the SHA-256 labhud pins:

  ```
  curl -fsSL http://labhud:8095/agent/install-agent.sh | sudo sh -s -- --url http://labhud:8095 --code <code>
  ```

- **No release pinned** (labhud from `main`, or before this agent's first release). The installer
  will not download what it cannot check: build the binary (below) or copy one, put it on the host
  as `./labhud-agent`, and pass the SHA-256 printed **where you built it**:

  ```
  curl -fsSL http://labhud:8095/agent/install-agent.sh -o install-agent.sh
  sudo sh install-agent.sh --url http://labhud:8095 --code <code> --binary ./labhud-agent --sha256 <sha256>
  ```

The installer writes `/etc/labhud-agent/config` (mode 600) and a systemd unit `labhud-agent`,
and on Proxmox VE a user `labhud@pve` with only `VM.PowerMgmt`, `VM.Audit` and `Sys.Audit` and a
token for it. `--ptero-url` adds a Pterodactyl panel (the key is asked for), `--base-w` and
`--price-kwh` set the power estimate. Run it again to upgrade, `--uninstall` to remove it.
Logs: `journalctl -u labhud-agent`.

As a container (`ghcr.io/mithrandler/labhud-agent`, from the first release on): ⚙ shows the
`docker run`, with the host's network, `/` read-only at `/host` and the Docker and D-Bus sockets.

## Settings

Read from `/etc/labhud-agent/config` (`KEY=VALUE` lines) and the environment, which wins.

| setting | |
|---|---|
| `LABHUD_URL` | labhud's address, `http://…:8095` or `https://…` |
| `LABHUD_AGENT_CODE` | the one-time pairing code from ⚙ > Agents (used once, 5 minutes) |
| `LABHUD_AGENT_NAME` | the name in labhud (default: the host name) |
| `LABHUD_AGENT_DIR` | settings and key folder (`/etc/labhud-agent`) |
| `LABHUD_AGENT_ROOT` | where the host's `/proc`, `/sys` and `/` are: `/host` in a container |
| `LABHUD_AGENT_RELEASES` | where its own updates come from (default: this repository's GitHub releases); set here, never by labhud |
| `LABHUD_AGENT_BASE_W`, `LABHUD_AGENT_PRICE_KWH` | fixed watts added to the power estimate; price per kWh |

After pairing the agent keeps its key in `<dir>/key` (mode 600). The key is derived from the
code on both sides and never travels; every frame is signed with it. The protocol is described
in labhud's [docs/agent-protocol.md](https://github.com/Mithrandler/labhud/blob/main/docs/agent-protocol.md).

Removed in labhud, the agent deletes its key and exits 0. A refused pairing exits 2.

## Updating

Installed as a service, the agent updates itself when labhud asks (⚙ > Agents > *Update to vX*,
`labhud agent update`, or *Update agents automatically*). labhud only names a version and its
SHA-256; the agent downloads that release from its own releases address, checks it against the
release's `SHA256SUMS` as well, takes only a version newer than its own, replaces its binary and
starts it again (same process, so systemd sees nothing). In a container it refuses: there the
image is the agent, so your image updater (or a new `docker run`) updates it. An agent older
than 0.1.0 does not know how: run labhud's install line once more.

## Building

```
CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=0.1.0" ./cmd/labhud-agent
sha256sum labhud-agent          # the --sha256 for the installer
go test ./... && go vet ./...
```

`GOARCH=arm64` for a Raspberry Pi or another ARM host.

## License

MIT
