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
# Runtime Stage (scratch with CA certs and users)
##############################
FROM scratch as final

LABEL org.opencontainers.image.source="https://github.com/finbourne/oidc-ingress" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.title="oidc-ingress" \
      org.opencontainers.image.licenses="Apache-2.0"

#This is a scratch image (is completely empty) so we need to copy the ca secrets to be able to handle ssl connections:
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# Copy /etc/passwd so we can get our low priv user
COPY --from=builder /etc/passwd /etc/passwd
#Copy binary and config:
COPY --from=builder /workspace/bin/oidc-ingress /usr/bin/oidc-ingress

USER nonroot

EXPOSE 8000 9000
ENTRYPOINT ["/usr/bin/oidc-ingress"]
