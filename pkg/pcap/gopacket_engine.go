package pcap

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gchux/pcap-cli/pkg/transformer"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var gopacketLogger = log.New(os.Stderr, "[gopacket] - ", log.LstdFlags)

func (p *Pcap) IsActive() bool {
	return p.isActive.Load()
}

func (p *Pcap) newPcap(ctx context.Context) (*pcap.InactiveHandle, error) {
	cfg := *p.config

	var err error

	inactiveHandle, err := pcap.NewInactiveHandle(cfg.Iface)
	if err != nil {
		gopacketLogger.Fatalf("could not create: %v\n", err)
	}

	if err = inactiveHandle.SetSnapLen(cfg.Snaplen); err != nil {
		gopacketLogger.Fatalf("could not set snap length: %v\n", err)
		return nil, err
	}

	if err = inactiveHandle.SetPromisc(cfg.Promisc); err != nil {
		gopacketLogger.Fatalf("could not set promisc mode: %v\n", err)
		return nil, err
	}

	// [TODO]: make handle timeout dynamic
	if err = inactiveHandle.SetTimeout(100 * time.Millisecond); err != nil {
		gopacketLogger.Fatalf("could not set timeout: %v\n", err)
		return nil, err
	}

	if cfg.TsType != "" {
		if t, err := pcap.TimestampSourceFromString(cfg.TsType); err != nil {
			gopacketLogger.Fatalf("Supported timestamp types: %v\n", inactiveHandle.SupportedTimestamps())
			return nil, err
		} else if err := inactiveHandle.SetTimestampSource(t); err != nil {
			gopacketLogger.Fatalf("Supported timestamp types: %v\n", inactiveHandle.SupportedTimestamps())
			return nil, err
		}
	}

	p.inactiveHandle = inactiveHandle

	return inactiveHandle, nil
}

func (p *Pcap) Start(ctx context.Context, writers []PcapWriter) error {
	// atomically activate the packet capture
	if !p.isActive.CompareAndSwap(false, true) {
		return fmt.Errorf("already started")
	}

	var err error
	var handle *pcap.Handle

	inactiveHandle, err := p.newPcap(ctx)
	if err != nil {
		return err
	}

	if handle, err = inactiveHandle.Activate(); err != nil {
		p.isActive.Store(false)
		return fmt.Errorf("failed to activate: %s", err)
	}
	p.activeHandle = handle

	cfg := *p.config
	debug := cfg.Debug

	// set packet capture filter; i/e: `tcp port 443`
	filter := cfg.Filter
	if filter != "" {
		if err = handle.SetBPFFilter(filter); err != nil {
			return fmt.Errorf("BPF filter error: %s", err)
		}
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	source.Lazy = false
	source.NoCopy = true
	source.DecodeStreamsAsDatagrams = true

	// intentionally not using `io.MultiWriter`
	pcapWriters := []PcapWriter{}
	// `io.Writer` is what `fmt.Fprintf` requires
	ioWriters := make([]io.Writer, len(writers))
	for i, writer := range writers {
		ioWriters[i] = writer
		pcapWriters = append(pcapWriters, writer)
	}

	device := cfg.Device
	iface := &transformer.PcapIface{
		Index: device.NetInterface.Index,
		Name:  device.Name,
		Addrs: device.Addresses,
	}

	format := cfg.Format

	// create new transformer for the specified output format
	var fn transformer.IPcapTransformer
	if cfg.Ordered {
		fn, err = transformer.NewOrderedTransformer(ctx, iface, ioWriters, &format, debug)
	} else if cfg.ConnTrack {
		fn, err = transformer.NewConnTrackTransformer(ctx, iface, ioWriters, &format, debug)
	} else {
		fn, err = transformer.NewTransformer(ctx, iface, ioWriters, &format, debug)
	}
	if err != nil {
		return fmt.Errorf("invalid format: %s", err)
	}
	p.fn = fn

	var packetsCounter atomic.Uint64
	for {
		select {
		case <-ctx.Done():
			gopacketLogger.Printf("[%d/%s] – stopping packet capture\n", device.NetInterface.Index, device.Name)
			inactiveHandle.CleanUp()
			handle.Close()
			gopacketLogger.Printf("[%d/%s] – raw sockets closed\n", device.NetInterface.Index, device.Name)
			fn.WaitDone(ctx, 2*time.Second)
			// do not close engine's writers until `stop` is called
			// if the context is done, simply rotate the current PCAP file
			// PCAP file rotation includes: flush and sync
			for _, writer := range pcapWriters {
				writer.rotate()
			}
			gopacketLogger.Printf("[%d/%s] – total packets: %d\n",
				device.NetInterface.Index, device.Name, packetsCounter.Load())
			p.isActive.Store(false)
			return ctx.Err()

		case packet := <-source.Packets():
			serial := packetsCounter.Add(1)
			// non-blocking operation
			if err := fn.Apply(ctx, &packet, &serial); err != nil {
				gopacketLogger.Fatalf("[%d] – failed to translate: %s\n", serial, packet)
			}
		}
	}
}

func NewPcap(config *PcapConfig) (PcapEngine, error) {
	var isActive atomic.Bool
	isActive.Store(false)

	debug := config.Debug
	if debugEnvVar, err := strconv.ParseBool(os.Getenv("PCAP_DEBUG")); err == nil {
		config.Debug = debug || debugEnvVar
	}

	pcap := Pcap{config: config, isActive: &isActive}

	devices, err := FindDevicesByName(&config.Iface)
	if err == nil {
		config.Device = devices[0]
	}

	return &pcap, nil
}
