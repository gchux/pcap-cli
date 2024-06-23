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

func (w pcapTranslatorWorker) pkt(ctx context.Context) gopacket.Packet {
	return *w.packet
}

func (w *pcapTranslatorWorker) asLayer(ctx context.Context, layer gopacket.LayerType) gopacket.Layer {
	return w.pkt(ctx).Layer(layer)
}

func (w *pcapTranslatorWorker) translateLayer(ctx context.Context, layer gopacket.LayerType) fmt.Stringer {
	l := w.asLayer(ctx, layer)
	if l == nil {
		return nil
	}

	switch lType := l.(type) {
	default:
		return nil
	case *layers.Ethernet:
		return w.translator.translateEthernetLayer(ctx, lType)
	case *layers.IPv4:
		return w.translator.translateIPv4Layer(ctx, lType)
	case *layers.IPv6:
		return w.translator.translateIPv6Layer(ctx, lType)
	case *layers.UDP:
		return w.translator.translateUDPLayer(ctx, lType)
	case *layers.TCP:
		return w.translator.translateTCPLayer(ctx, lType)
	case *layers.TLS:
		return w.translator.translateTLSLayer(ctx, lType)
	case *layers.DNS:
		return w.translator.translateDNSLayer(ctx, lType)
	}
}

func (w pcapTranslatorWorker) translateEthernetLayer(ctx context.Context) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeEthernet)
}

func (w *pcapTranslatorWorker) translateIPv4Layer(ctx context.Context) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeIPv4)
}

func (w *pcapTranslatorWorker) translateIPv6Layer(ctx context.Context) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeIPv6)
}

func (w *pcapTranslatorWorker) translateUDPLayer(ctx context.Context) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeUDP)
}

func (w *pcapTranslatorWorker) translateTCPLayer(ctx context.Context) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeTCP)
}

func (w *pcapTranslatorWorker) translateDNSLayer(ctx context.Context) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeDNS)
}

func (w *pcapTranslatorWorker) translateTLSLayer(ctx context.Context) fmt.Stringer {
	/*
		packet := w.pkt(ctx)
		if packet.ApplicationLayer() != nil {
			var tls layers.TLS
			var decoded []gopacket.LayerType
			parser := gopacket.NewDecodingLayerParser(layers.LayerTypeTLS, &tls)
			err := parser.DecodeLayers(packet.ApplicationLayer().LayerContents(), &decoded)
			if err == nil {
				for _, layerType := range decoded {
					switch layerType {
					case layers.LayerTypeTLS:
						return w.translator.translateTLSLayer(ctx, &tls)
					}
				}
			}
		}
	*/

	return w.translateLayer(ctx, layers.LayerTypeTLS)
}

// The work that needs to be performed
// The input type should implement the WorkFunction interface
func (w *pcapTranslatorWorker) Run(ctx context.Context) interface{} {
	buffer := w.translator.next(ctx, w.packet, w.serial)

	// alternatives per layer; there can only be one!
	translators := [][]packetLayerTranslator{
		{w.translateEthernetLayer},                   // L2
		{w.translateIPv4Layer, w.translateIPv6Layer}, // L3
		{w.translateTCPLayer, w.translateUDPLayer},   // L4
		{w.translateDNSLayer, w.translateTLSLayer},   // L7
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
