# syntax=docker/dockerfile:1.4

FROM golang:1.22.4-bookworm AS build

ARG DEBIAN_FRONTEND=noninteractive

USER 0:0

RUN apt-get -qq update > /dev/null
RUN apt-get install -qq -y libpcap-dev 
RUN apt-get -qq clean > /dev/null

WORKDIR /app

ADD . /app

ENV GOOS=linux
ENV GOARCH=amd64

RUN go install golang.org/x/tools/cmd/stringer@latest
RUN go mod download
RUN go fmt ./...
RUN go generate ./...
RUN go build -a -v -o /app/pcap cmd/pcap.go

FROM scratch AS releaser
COPY --link --from=build /app/pcap /
