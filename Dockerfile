# syntax=docker/dockerfile:1.4

FROM --platform=linux/amd64 golang:1.22.4-bookworm AS builder

ARG DEBIAN_FRONTEND=noninteractive
ARG BIN_NAME=pcap

WORKDIR /app
ADD . /app

USER 0:0

RUN apt-get -qq update > /dev/null
RUN apt-get install -qq -y libpcap-dev 
RUN apt-get -qq clean > /dev/null

RUN go install mvdan.cc/gofumpt@latest
RUN go install golang.org/x/tools/cmd/stringer@latest

ENV GOOS=linux
ENV GOARCH=amd64

RUN go mod tidy -compat=1.22.4
RUN go mod download
RUN gofumpt -l -w ./cmd/
RUN gofumpt -l -w ./pkg/
RUN go generate ./pkg/...
RUN go build -a -v -o /app/bin/${BIN_NAME} cmd/pcap.go

FROM scratch AS releaser
COPY --link --from=builder /app/bin/${BIN_NAME} /
