# syntax=docker/dockerfile:1.7

FROM golang:1.26-bookworm AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -trimpath \
  -ldflags "-s -w -X kubescan/internal/buildinfo.Version=${VERSION} -X kubescan/internal/buildinfo.Commit=${COMMIT} -X kubescan/internal/buildinfo.Date=${DATE}" \
  -o /out/kubescan ./cmd/kubescan

FROM alpine:3.22

ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

LABEL org.opencontainers.image.title="kubescan" \
      org.opencontainers.image.description="Kubernetes security analysis CLI" \
      org.opencontainers.image.url="https://github.com/automatesecurity/kubescan" \
      org.opencontainers.image.source="https://github.com/automatesecurity/kubescan" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${DATE}"

RUN apk add --no-cache ca-certificates git && \
  addgroup -S kubescan && \
  adduser -S -G kubescan -u 65532 kubescan

WORKDIR /workspace

COPY --from=builder /out/kubescan /usr/local/bin/kubescan

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/kubescan"]
