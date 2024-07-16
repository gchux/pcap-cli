package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/gchux/pcap-cli/pkg/pcap"
	"github.com/google/uuid"
)

var (
	engine    = flag.String("eng", "google", "Engine to use for capturing packets: tcpdump or google")
	iface     = flag.String("i", "any", "Interface to read packets from")
	snaplen   = flag.Int("s", 0, "Snap length (number of bytes max to read per packet")
	writeTo   = flag.String("w", "stdout", "Where to write packet capture to: stdout or a file path")
	tsType    = flag.String("ts_type", "", "Type of timestamps to use")
	promisc   = flag.Bool("promisc", true, "Set promiscuous mode")
	format    = flag.String("fmt", "default", "Set the output format: default, text or json")
	filter    = flag.String("filter", "", "Set BPF filter to be used")
	timeout   = flag.Int("timeout", 0, "Set packet capturing total duration in seconds")
	interval  = flag.Int("interval", 0, "Set packet capture file rotation interval in seconds")
	extension = flag.String("ext", "", "Set pcap files extension: pcap, json, txt")
	stdout    = flag.Bool("stdout", false, "Log translation to standard output; only if 'w' is not 'stdout'")
	ordered   = flag.Bool("ordered", false, "write translation in the order in which packets were captured")
	conntrack = flag.Bool("conntrack", false, "enable connection tracking (includes 'ordered')")
	timezone  = flag.String("tz", "UTC", "timezone to be used by PCAP files template")
)

var logger = log.New(os.Stderr, "[pcap] - ", log.LstdFlags)

func handleError(prefix *string, err error) {
	if errors.Is(err, context.Canceled) {
		logger.Printf("%s cancelled\n", *prefix)
		os.Exit(1)
	}

	if errors.Is(err, context.DeadlineExceeded) {
		logger.Printf("%s complete\n", *prefix)
	}
}

func newPcapEngine(engine *string, config *pcap.PcapConfig) (pcap.PcapEngine, error) {
	pcapEngine := *engine

	switch pcapEngine {
	case "google":
		return pcap.NewPcap(config)
	case "tcpdump":
		return pcap.NewTcpdump(config)
	default:
		/* no-go */
	}

	return nil, fmt.Errorf("unavailable: %s", pcapEngine)
}

func main() {
	flag.Parse()

	config := &pcap.PcapConfig{
		Promisc:   *promisc,
		Snaplen:   *snaplen,
		TsType:    *tsType,
		Format:    *format,
		Filter:    *filter,
		Output:    *writeTo,
		Interval:  *interval,
		Extension: *extension,
		Ordered:   *ordered,
		ConnTrack: *conntrack,
	}

	exp, _ := regexp.Compile(fmt.Sprintf("^(?:ipvlan-)?%s.*", *iface))
	devs, _ := pcap.FindDevicesByRegex(exp)

	ctx := context.Background()
	var cancel context.CancelFunc

	id := fmt.Sprintf("cli/%s", uuid.New())
	ctx = context.WithValue(ctx, pcap.PcapContextID, id)
	ctx = context.WithValue(ctx, pcap.PcapContextLogName, `log/`+id)

	if *timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(*timeout)*time.Second)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}

	var wg sync.WaitGroup

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signals
		cancel()
	}()

	for _, dev := range devs {
		wg.Add(1)
		go startPCAP(ctx, &id, dev, config, &wg)
	}
	wg.Wait()
}

func startPCAP(ctx context.Context, id *string, dev *pcap.PcapDevice, config *pcap.PcapConfig, wg *sync.WaitGroup) {
	iface := dev.NetInterface.Name

	logger.Printf("device: %+v\n", iface)

	config.Iface = iface

	if *engine == "tcpdump" && *stdout {
		*writeTo = "stdout"
	}

	var err error
	var pcapEngine pcap.PcapEngine

	pcapEngine, err = newPcapEngine(engine, config)
	if err != nil {
		log.Fatalf("%s", err)
		return
	}

	if *writeTo == "stdout" {
		*stdout = true
	}

	pcapWriters := []pcap.PcapWriter{}
	var pcapWriter pcap.PcapWriter

	if *engine == "google" && *stdout {
		pcapWriter, err = pcap.NewStdoutPcapWriter()
		if err == nil {
			pcapWriters = append(pcapWriters, pcapWriter)
		}
	}

	if *engine == "google" && *writeTo != "stdout" {
		pcapWriter, err = pcap.NewPcapWriter(writeTo, extension, timezone, *interval)
		if err == nil {
			pcapWriters = append(pcapWriters, pcapWriter)
		}
	}

	prefix := fmt.Sprintf("[iface:%s] execution '%s'", iface, *id)
	logger.Printf("%s started", prefix)
	// this is a blocking call
	err = pcapEngine.Start(ctx, pcapWriters)
	if err != nil {
		handleError(&prefix, err)
	}
	wg.Done()
}
