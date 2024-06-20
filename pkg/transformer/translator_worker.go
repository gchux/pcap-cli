package transformer

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type (
	pcapTranslatorWorker struct {
		serial     *uint64
		packet     *gopacket.Packet
		translator PcapTranslator
	}

	packetLayerTranslator func(context.Context) fmt.Stringer
)

//go:generate stringer -type=PcapTranslatorFmt
const (
	TEXT PcapTranslatorFmt = iota
	JSON
)

var pcapTranslatorFmts = map[string]PcapTranslatorFmt{
	"json": JSON,
	"text": TEXT,
}

func (w pcapTranslatorWorker) pkt() gopacket.Packet {
	return *w.packet
}

func (w pcapTranslatorWorker) asLayer(layer gopacket.LayerType) gopacket.Layer {
	return w.pkt().Layer(layer)
}

func (w pcapTranslatorWorker) translateEthernetLayer(ctx context.Context) fmt.Stringer {
	ethernetLayer := w.asLayer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		return w.translator.translateEthernetLayer(ctx, ethernetPacket)
	}
	return nil
}

func (w pcapTranslatorWorker) translateIPv4Layer(ctx context.Context) fmt.Stringer {
	ipLayer := w.asLayer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ipPacket, _ := ipLayer.(*layers.IPv4)
		return w.translator.translateIPv4Layer(ctx, ipPacket)
	}
	return nil
}

func (w pcapTranslatorWorker) translateIPv6Layer(ctx context.Context) fmt.Stringer {
	ipLayer := w.asLayer(layers.LayerTypeIPv6)
	if ipLayer != nil {
		ipPacket, _ := ipLayer.(*layers.IPv6)
		return w.translator.translateIPv6Layer(ctx, ipPacket)
	}
	return nil
}

func (w pcapTranslatorWorker) translateUDPLayer(ctx context.Context) fmt.Stringer {
	tcpLayer := w.asLayer(layers.LayerTypeUDP)
	if tcpLayer != nil {
		tcpPacket, _ := tcpLayer.(*layers.UDP)
		return w.translator.translateUDPLayer(ctx, tcpPacket)
	}
	return nil
}

func (w pcapTranslatorWorker) translateTCPLayer(ctx context.Context) fmt.Stringer {
	tcpLayer := w.asLayer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcpPacket, _ := tcpLayer.(*layers.TCP)
		return w.translator.translateTCPLayer(ctx, tcpPacket)
	}
	return nil
}

// The work that needs to be performed
// The input type should implement the WorkFunction interface
func (w pcapTranslatorWorker) Run(ctx context.Context) interface{} {
	buffer := w.translator.next(ctx, w.packet, w.serial)

	// alternatives per layer; there can only be one!
	translators := [][]packetLayerTranslator{
		{w.translateEthernetLayer},                   // L2
		{w.translateIPv4Layer, w.translateIPv6Layer}, // L3
		{w.translateTCPLayer, w.translateUDPLayer},   // L4
	}

	numLayers := len(translators)
	translations := make(chan fmt.Stringer, numLayers)
	var wg sync.WaitGroup
	wg.Add(numLayers) // number of layers to be translated

	go func() {
		wg.Wait()
		close(translations)
	}()

	for _, translators := range translators {
		go func(translators []packetLayerTranslator) {
			for _, translator := range translators {
				if t := translator(ctx); t != nil {
					translations <- t
					// skip next alternatives
					break
				}
			}
			wg.Done()
		}(translators)
	}

	for translation := range translations {
		// translations are `nil` if layer is not available
		if translation != nil {
			buffer, _ = w.translator.merge(ctx, buffer, translation)
		}
	}

	buffer, _ = w.translator.finalize(ctx, buffer)

	return &buffer
}
