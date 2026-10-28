# Multi-stage build: a static Go binary on distroless. Both bases are pinned by
# digest so a rebuild is reproducible; bump tag + digest together
# (`docker pull <image>:<tag>` then `docker image inspect --format '{{index .RepoDigests 0}}'`).
# Toolchain matches go.mod `toolchain`; Go 1.24 is EOL with unfixed stdlib CVEs.
FROM golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS build

WORKDIR /src

# Module download first (better layer caching).
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o /out/fleethound ./cmd/fleethound

# distroless has no shell: pre-create the writable config tree here.
RUN mkdir -p /out/config/snapshots

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

WORKDIR /app

COPY --from=build /out/fleethound /usr/local/bin/fleethound
COPY webviz/static/ /app/webviz/static/

# Config dir is mounted as a volume in docker-compose. uid 10001 matches the
# previous python image ('webviz'), so existing bind-mounted config files
# (whitelist.json, audit.log, snapshots, state) stay writable.
# Default known-publisher list and threat feeds for deployments that don't
# bind-mount config/ (compose mounts ./config over /app/config).
COPY --from=build --chown=10001:10001 /out/config/ /app/config/
COPY --chown=10001:10001 config/known_publishers.json config/extension_threat_feeds.json /app/config/

USER 10001:10001

# Fail-closed default for prod image: refuse to start unless WEBVIZ_API_TOKEN
# is supplied (via env or *_FILE secret mount). Operators must explicitly opt
# out by setting WEBVIZ_REQUIRE_AUTH=false in their compose/k8s spec.
ENV WEBVIZ_REQUIRE_AUTH=true
# Container network: listen on all interfaces (compose publishes loopback only).
ENV WEBVIZ_BIND_HOST=0.0.0.0

EXPOSE 8080

# Lightweight /api/health (database ping), not /api/graph (heavy query).
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/fleethound", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/fleethound"]
CMD ["serve"]
