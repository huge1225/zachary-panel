FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o panel-server ./cmd/server
RUN CGO_ENABLED=0 GOOS=linux go build -o panel-agent ./cmd/agent

FROM alpine:3.19 AS server
RUN apk add --no-cache ca-certificates nftables
COPY --from=builder /build/panel-server /usr/bin/panel-server
EXPOSE 8080 9090
VOLUME /data
ENTRYPOINT ["panel-server"]

FROM alpine:3.19 AS agent
RUN apk add --no-cache ca-certificates nftables
COPY --from=builder /build/panel-agent /usr/bin/panel-agent
# 安装 gost
RUN wget -qO- https://github.com/ginuerzh/gost/releases/download/v2.12.0/gost-linux-amd64-2.12.0.gz | gunzip > /usr/bin/gost && chmod +x /usr/bin/gost
ENTRYPOINT ["panel-agent"]
