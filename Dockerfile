# syntax=docker/dockerfile:1
FROM golang:1.26-bookworm AS builder
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY web ./web
RUN CGO_ENABLED=0 go test ./... && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/tor-country-manager .

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends tor tor-geoipdb ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin tor-manager && \
    mkdir -p /app /data && chown -R tor-manager:tor-manager /data
COPY --from=builder /out/tor-country-manager /usr/local/bin/tor-country-manager
COPY deploy/docker/config.json /app/config.default.json
COPY --chmod=0755 deploy/docker/entrypoint.sh /usr/local/bin/docker-entrypoint.sh
USER tor-manager
VOLUME ["/data"]
EXPOSE 8080 1080 20000-20675
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
