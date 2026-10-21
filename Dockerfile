# A static binary on an empty image. It runs as root inside: it talks to the Docker socket and to
# systemd over D-Bus. What it may do is decided in labhud's ⚙ > Agents and checked by the agent.
#
#   docker run -d --name labhud-agent --restart unless-stopped --network host \
#     -v /:/host:ro -v /var/run/docker.sock:/var/run/docker.sock \
#     -v /run/dbus/system_bus_socket:/var/run/dbus/system_bus_socket \
#     -v labhud-agent:/etc/labhud-agent \
#     -e LABHUD_URL=http://<labhud>:8095 -e LABHUD_AGENT_CODE=<code> <this image>
#
# --network host: Wake-on-LAN and the ARP table; / read-only at /host: the host's sensors, disk
# and name. Leave out a socket and that capability is simply not found.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X main.version=$VERSION" -o /labhud-agent ./cmd/labhud-agent

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /labhud-agent /labhud-agent
ENV LABHUD_AGENT_DIR=/etc/labhud-agent LABHUD_AGENT_ROOT=/host
VOLUME /etc/labhud-agent
ARG VERSION=dev
LABEL org.opencontainers.image.title="labhud-agent" \
      org.opencontainers.image.description="The agent of labhud: one per host, acts through its local APIs" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/Mithrandler/labhud-agent"
ENTRYPOINT ["/labhud-agent"]
