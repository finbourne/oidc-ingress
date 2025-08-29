# syntax=docker/dockerfile:1.7

##############################
# Builder Stage
##############################
FROM golang:1.25-alpine AS builder

ARG VERSION=""
ARG GIT_COMMIT=""

# Install build deps only if/when needed (kept minimal)
RUN apk add --no-cache git

WORKDIR /workspace

# First copy go.mod/sum to leverage layer caching
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy the rest of the source
COPY . .

# Build binary (static, trimmed)
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=$(go env GOARCH) \
    go build -trimpath -ldflags "-s -w -X main.GitCommit=${GIT_COMMIT} -X main.VersionPrerelease=${VERSION}" \
    -o /workspace/bin/oidc-ingress ./cmd/oidc-ingress

##############################
# Runtime Stage (distroless with CA certs)
##############################
FROM gcr.io/distroless/base-debian12:nonroot

LABEL org.opencontainers.image.source="https://github.com/finbourne/oidc-ingress" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.title="oidc-ingress" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /workspace/bin/oidc-ingress /usr/bin/oidc-ingress

USER nonroot

EXPOSE 8000 9000
ENTRYPOINT ["/usr/bin/oidc-ingress"]
