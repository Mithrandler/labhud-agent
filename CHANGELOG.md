# Changelog

## [Unreleased]

### Added

- **Streams**: labhud can `open` a live stream on a ticked container and receive `chunk`s until an `end`
  (the messages `open`, `input`, `resize`, `close`, `chunk`, `end`; at most 3 open on a connection, closed
  with it). `docker` `follow`: the container's log, 50 lines back, then live, read only, closes after 10
  minutes. `terminal` `shell`: a shell (bash, else sh) in the container through `docker exec` with a TTY,
  closes after 15 minutes or 3 without a key, only when the agent is started with
  `LABHUD_AGENT_TERMINAL=on` and the container is ticked under *Terminal* (a tick of its own, not
  docker's). Nothing that goes through a stream is logged or kept.
- **Stacks (compose)**, off unless `LABHUD_AGENT_STACKS=<folder>` is set and the host has `docker compose`
  (or `docker-compose`): the capability `stacks`, a folder per stack holding `compose.yaml` and an optional
  `.env`. Verbs: `deploy` (the files arrive sealed, up to 64 KiB, are written with mode 0600, checked with
  `compose config` in a scratch folder first, then `up -d --remove-orphans`; a broken file leaves the old
  one), `redeploy` (pull, then up), `restart`, `down` (never removes volumes) and `show` (the file, the
  `.env` by name only). It is the one capability that runs a program: the program is found once at start,
  the arguments are built in the agent, no shell, an environment of five variables. A compose file can ask
  for what the Docker socket can, so ticking it is as strong as that. Not for the container image (it has
  no docker CLI): use the service install.
- **The host's Docker, whole**: on the target `images` (ticked like a container), the read verb `inventory`
  lists the images (size, tags, containers using each, untagged), the volumes (size, users, anonymous or
  named) and the networks (containers on each), the biggest first, at most 100 of each. New cleaning
  verbs beside `prune`: `prune-dangling` (untagged layers), `prune-networks` (user-made networks no
  container is on, a day old at least) and `prune-volumes` (only anonymous volumes nothing uses: the
  agent picks them itself and never removes a named volume). All of them are for `images` and nothing else.

## [0.1.0] - 2026-10-21

The first version, with labhud 0.1.0 (the agent, the server and the app share a version from now).

### Added

- **Registry logins in an update command**: a private registry's login (user and token) reaches the
  agent sealed, never in the clear, and only in the command that needs it.
- **The image scan capability**: with trivy or grype on the host, the critical and high CVEs of a
  ticked container's image, so labhud can hold an update back.
- A container's `labhud.*` labels in the state (`labels`; at most 16, no other label): labhud makes
  a card from `labhud.name`, `labhud.url`, `labhud.page`…
- `inspect`, a Docker read verb: how a container is made (ports, mounts, networks, restart policy,
  labels, health, command), the environment by name only, labels and a command that look secret
  without their values.
- `LABHUD_AGENT_AUTO_LABELS` ("k=v,k2=v2"): labels a container gets when it is made again while
  labhud updates it on its own (`allow.auto`), and loses when it no longer does; e.g.
  `dockhand.update=false`, so that Dockhand leaves those to labhud.
- **A ticked container that stops by itself** is an event for labhud's timeline: "stopped by itself
  (exit code 1)", "ran out of memory", and once, "keeps stopping: 3 times in 10 minutes" (then
  quiet for 30 minutes). Read from the engine's events; a stop someone asked for (a kill first)
  and an update's own stop are left out.
- **Usage per container**: a ticked container that runs has `cpu` (% of one core, as `docker
  stats`), `mem` (bytes, without the page cache), `mem_pct`, `net_rx`/`net_tx` (bytes a second)
  and `restarts`, measured every 30 s.
- **Compose project**: each container's `project` (its `com.docker.compose.project` label).
- **Clean unused images**: `docker` `prune` on the target `images` (ticked in labhud like a
  container) removes the images no container uses, unused for 24 hours at least, and answers what
  it freed. `images` is a target for nothing else, and prune for nothing else.
- **Failed systemd units**: `failed_units` in the state, every unit in the failed state (any type,
  ticked or not; names only).
- Events say what they are about (`cap`, `target`, `kind`, and for an update `from` and `to`:
  the image's `org.opencontainers.image.version`, else its short id), for labhud's update history.
- **Updates itself** when labhud asks: labhud names a version and its SHA-256, the agent downloads
  it from its own releases (`LABHUD_AGENT_RELEASES` on the host, else GitHub), checks it against
  the release's SHA256SUMS too, takes only a newer version, replaces its binary and execs it. In a
  container it refuses (the image is updated instead).
- `hello` says how it runs: `install` is `service` or `container`.
- The image is published to `ghcr.io/mithrandler/labhud-agent` (0.1.0, 0.1, latest) by CI with
  its own token.
- Pairs with labhud from a one-time code: the key is derived on both sides and never sent;
  labhud proves it knows the code too, and vouches for its TLS certificate, which is then pinned.
- Every frame signed (HMAC-SHA256), bound to its connection, numbered, at most 30 s old.
- Capabilities, each found by itself and off until ticked in labhud: sensors (CPU, memory, disk,
  temperatures, NVIDIA GPUs, RAPL power), Docker, systemd units, the host (reboot, shut down,
  update packages in a transient unit), Wake-on-LAN, Proxmox VE guests, Pterodactyl servers.
- Every command checked against labhud's allowlist again, in the agent. Never a shell.
- Docker: `update` (pull the tag, then the container again with the same settings and networks,
  without what came from its old image; the old one is kept until the new one stays up 15 s, and
  put back if not; never the agent's own container) and `logs` (the last 200 lines, without colour
  codes, at most 48 KiB, sent back as the result's `output`). A ticked container has
  `"update": true` when its registry has a newer digest for its tag (every 6 hours).
- Sensors: `net_rx` / `net_tx`, bytes a second over the physical interfaces.
- A Pterodactyl panel with a self-signed certificate: `LABHUD_PTERO_PIN` (its SHA-256) accepts that
  certificate and no other.

[Unreleased]: https://github.com/Mithrandler/labhud-agent/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Mithrandler/labhud-agent/releases/tag/v0.1.0
