# syntax=docker/dockerfile:1
#
# Packages the Unified Data Repository (UDR) from this bundle's source snapshot
# in pkgs/udr (upstream github.com/free5gc/udr, branch main @ db69aa0e == tag v1.4.5).
#
# Structure follows /root/5gc/free5gc-compose:
#   base/Dockerfile.nf  -> compile stage (Go toolchain, sources under $GOPATH/src/free5gc)
#   nf_udr/Dockerfile   -> runtime stage (alpine:3.15, /free5gc layout, EXPOSE 8000)
#
# Two deviations, both forced by building the standalone NF repository instead of
# the free5gc monorepo:
#   1. the toolchain is golang:1.26.2, because pkgs/udr/go.mod declares `go 1.26.2`
#      while upstream's base image is golang:1.21.8 and cannot compile this module;
#   2. the compile command is `go build ./cmd`, because the standalone repository
#      carries no Makefile (the monorepo runs `make udr` for the same main package).
#
# Default certificates are NOT baked in: the deployment bind-mounts free5gc/cert
# over /free5gc/cert, exactly as 5gc-deployments/free5gc/issues/1189 does.
#
# Build (context = this directory):
#   docker build -f Dockerfile -t free5gc/udr:v1.4.5-db69aa0 .

FROM golang:1.26.2-bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /go/src/free5gc/NFs/udr

# Resolve dependencies first so the compile layer is re-run on source-only edits.
COPY pkgs/udr/go.mod pkgs/udr/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY pkgs/udr/ ./

# The UDR is pure Go (gin + mongo driver), so CGO is disabled for a static binary;
# no libmnl/libyaml build deps are needed as they are for the UPF/SMF.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-w -s" -o /go/bin/udr ./cmd \
    && /go/bin/udr --help >/dev/null \
    && ldd /go/bin/udr 2>&1 | head -3

FROM alpine:3.15
`
# Revision baked into the provenance label; override with
# --build-arg REVISION=$(git -C pkgs/udr rev-parse HEAD) when building from a
# different commit of pkgs/udr (e.g. the fix branch).
ARG REVISION=db69aa0e5b827306d4b8f1420c98fc13300ead66

LABEL description="Free5GC UDR built from this bundle's source snapshot (free5gc/udr main)" \
    version="v1.4.5" \
    org.opencontainers.image.source="https://github.com/free5gc/udr" \
    org.opencontainers.image.revision="${REVISION}"

ARG DEBUG_TOOLS

ENV F5GC_MODULE=udr

# Install debug tools ~ 100MB (if DEBUG_TOOLS is set to true)
RUN if [ "$DEBUG_TOOLS" = "true" ] ; then apk add -U vim strace net-tools curl netcat-openbsd ; fi

# Set working dir
WORKDIR /free5gc
RUN mkdir -p config/ log/ cert/

# Copy executable (certs and configs come from the deployment's bind mounts)
COPY --from=builder /go/bin/udr ./

# Config files volume
VOLUME [ "/free5gc/config" ]

# Certificates (if not using default) volume
VOLUME [ "/free5gc/cert" ]

# Exposed ports
EXPOSE 8000
