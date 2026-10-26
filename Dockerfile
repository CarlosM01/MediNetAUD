# The Go toolchain only exists in the build stage. Each runtime image carries one static binary
# on plain alpine: `api` (the default target) and `audctl` (--target audctl), kept apart so the
# service image stays small and the admin tool never runs in the service container.
FROM golang:1.26.10-alpine3.24 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/audctl ./cmd/audctl

FROM alpine:3.24.3 AS runtime
RUN addgroup -g 10001 app \
 && adduser -D -H -u 10001 -G app -s /sbin/nologin app
USER app

FROM runtime AS audctl
COPY --from=build /out/audctl /usr/local/bin/audctl
ENTRYPOINT ["audctl"]

FROM runtime AS api
COPY --from=build /out/api /usr/local/bin/api
EXPOSE 8080
# Probes the default HTTP_ADDR (:8080); change it here too if the service listens elsewhere.
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["api"]
