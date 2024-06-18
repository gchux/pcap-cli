# How to build

## Dependencies

- [`libpcap-dev`](https://github.com/the-tcpdump-group/libpcap): install from distro repos
- [`stringer`](https://pkg.go.dev/golang.org/x/tools/cmd/stringer): `go install golang.org/x/tools/cmd/stringer@latest`

## Using `go`

```sh
go generate ./...
go build -o bin/pcap cmd/pcap.go
```

> **NOTE**: apply [`gofumpt`](https://github.com/mvdan/gofumpt) before commit; i/e: `gofumpt -l -w .`

## Using [Taskfile](https://taskfile.dev/)

### Quick build

```sh
task -v build
```

### Verbose build

```sh
task -v dist
```

### Docker build

```sh
task -v docker-build
```

# How to use

## Using [`goacket`](https://github.com/google/gopacket) engine

### Generating JSON

```sh
sudo pcap -eng=google -promisc -i ${IFACE} -s ${SNAPLEN} -fmt=json -stdout -filter='tcp'
```

#### Generating ordered JSON

```sh
sudo pcap -eng=google -promisc -i ${IFACE} -s ${SNAPLEN} -fmt=json -stdout -filter='tcp' -ordered
```

### Generating console output and JSON files

```sh
sudo pcap -eng=google -promisc -i ${IFACE} -s ${SNAPLEN} -w part_%Y%m%d_%H%M%S -ext=json -fmt=json -stdout -filter='tcp'
```

#### Terminate execution after defined seconds

```sh
sudo pcap -eng=google -promisc \
  -i ${IFACE} -s ${SNAPLEN} \
  -w part_%Y%m%d_%H%M%S -ext=json \
  -fmt=json -stdout \
  -timeout=60 -filter='tcp'
```

#### Terminate execution after defined seconds and rotate every defined seconds

```sh
sudo pcap -eng=google -promisc \
  -i ${IFACE} -s ${SNAPLEN} \
  -w part_%Y%m%d_%H%M%S -ext=json \
  -fmt=json -stdout \
  -timeout=60 -interval=10 -filter='tcp'
```
