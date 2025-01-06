// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transformer

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type (
	pcapTranslatorWorker struct {
		iface        *PcapIface
		serial       *uint64
		packet       *gopacket.Packet
		translator   PcapTranslator
		conntrack    bool
		loggerPrefix *string
	}

	packetLayerTranslator func(context.Context, *pcapTranslatorWorker) fmt.Stringer

	httpRequest struct {
		timestamp   *time.Time
		url, method *string
	}

	traceAndSpan struct {
		traceID, spanID *string
		streamID        *uint32
	}
)

var (
	// alternatives per layer; there can only be one!
	packetLayerTranslators = [][]packetLayerTranslator{
		{ // L2
			func(ctx context.Context, w *pcapTranslatorWorker) fmt.Stringer {
				return w.translateEthernetLayer(ctx)
			},
		},
		{ // L3
			func(ctx context.Context, w *pcapTranslatorWorker) fmt.Stringer {
				return w.translateIPv4Layer(ctx)
			},
			func(ctx context.Context, w *pcapTranslatorWorker) fmt.Stringer {
				return w.translateIPv6Layer(ctx)
			},
		},
		{ // L4
			// ICMP layers
			//   - ICMP is not a transport layer protocol, but if it is present
			//   - then actual transport layer protocol translations are disabled;
			//   - thus, TCP/UDP translations are causally dependant on the lack of ICMP.
			func(ctx context.Context, w *pcapTranslatorWorker) fmt.Stringer {
				return w.translateICMPv4Layer(ctx)
			},
			func(ctx context.Context, w *pcapTranslatorWorker) fmt.Stringer {
				return w.translateICMPv6Layer(ctx)
			},
			// non-ICMP layers
			func(ctx context.Context, w *pcapTranslatorWorker) fmt.Stringer {
				return w.translateTCPLayer(ctx)
			},
			func(ctx context.Context, w *pcapTranslatorWorker) fmt.Stringer {
				return w.translateUDPLayer(ctx)
			},
		},
		{ // L7
			func(ctx context.Context, w *pcapTranslatorWorker) fmt.Stringer {
				return w.translateDNSLayer(ctx)
			},
			func(ctx context.Context, w *pcapTranslatorWorker) fmt.Stringer {
				return w.translateTLSLayer(ctx)
			},
		},
	}

	packetLayerTranslatorsSize = len(packetLayerTranslators)
)

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
	case *layers.ICMPv4:
		return w.translator.translateICMPv4Layer(ctx, lType)
	case *layers.ICMPv6:
		icmp6 := w.translator.translateICMPv6Layer(ctx, lType)
		_l := w.asLayer(ctx, lType.NextLayerType())
		switch _lType := _l.(type) {
		default:
			if lType.TypeCode.Type() == layers.ICMPv6TypeDestinationUnreachable ||
				lType.TypeCode.Type() == layers.ICMPv6TypeTimeExceeded {
				return w.translator.translateICMPv6L3HeaderLayer(ctx, icmp6, lType)
			}
			return icmp6
		case *layers.ICMPv6Echo:
			return w.translator.translateICMPv6EchoLayer(ctx, icmp6, _lType)
		case *layers.ICMPv6Redirect:
			return w.translator.translateICMPv6RedirectLayer(ctx, icmp6, _lType)
		}
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

func (w *pcapTranslatorWorker) translateICMPv4Layer(ctx context.Context) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeICMPv4)
}

func (w *pcapTranslatorWorker) translateICMPv6Layer(ctx context.Context) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeICMPv6)
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
func (w *pcapTranslatorWorker) Run(ctx context.Context) (buffer interface{}) {
	defer func() {
		if r := recover(); r != nil {
			transformerLogger.Printf("%s @translator | panic: %s\n%s\n",
				*w.loggerPrefix, r, string(debug.Stack()))
			buffer = nil
		}
	}()

	var _buffer fmt.Stringer = nil

	select {
	case <-ctx.Done():
		_buffer = nil
	default:
		_buffer = w.translator.next(ctx, w.iface, w.serial, w.packet)
	}

	if _buffer == nil {
		transformerLogger.Printf("%s @translator | failed", *w.loggerPrefix)
		buffer = nil
		return nil
	}

	translations := make(chan fmt.Stringer, packetLayerTranslatorsSize)
	var wg sync.WaitGroup
	wg.Add(packetLayerTranslatorsSize) // number of layers to be translated

	go func(wg *sync.WaitGroup) {
		wg.Wait()
		close(translations)
	}(&wg)

	// O(N*M)
	//   - N: layers
	//   - M: protocols
	// [ToDo]: implement as a `Map` to translate layers+protocols to translation in O(1)
	for i, translators := range packetLayerTranslators {
		// translate layers concurrently:
		//   - layers must know nothing about each other
		go func(index int, translators []packetLayerTranslator, wg *sync.WaitGroup) {
			defer func(index int, wg *sync.WaitGroup) {
				if r := recover(); r != nil {
					transformerLogger.Printf("%s @translator[%d] | panic: %s\n%s\n",
						*w.loggerPrefix, index, r, string(debug.Stack()))
					buffer = nil
				}
				wg.Done()
			}(index, wg)

			for _, translator := range translators {
				if t := translator(ctx, w); t != nil {
					translations <- t
					break // skip next alternatives
				}
			}
		}(i, translators, &wg)
	}

	for translation := range translations {
		// translations are `nil` if layer is not available
		if translation != nil {
			_buffer, _ = w.translator.merge(ctx, _buffer, translation)
		}
	}

	select {
	case <-ctx.Done():
		// skip `finalize` deliver translation as-is
		transformerLogger.Printf("%s @translator | incomplete", *w.loggerPrefix)
	default:
		// `finalize` is the only method that works across layers
		_buffer, _ = w.translator.finalize(ctx, w.iface, w.serial, w.packet, w.conntrack, _buffer)
	}

	buffer = &_buffer
	return &_buffer
}

func newPcapTranslatorWorker(
	iface *PcapIface,
	serial *uint64,
	packet *gopacket.Packet,
	translator PcapTranslator,
	connTrack bool,
) *pcapTranslatorWorker {
	loggerPrefix := fmt.Sprintf("[%d/%s] - #:%d |", iface.Index, iface.Name, *serial)

	worker := &pcapTranslatorWorker{
		iface:        iface,
		serial:       serial,
		packet:       packet,
		translator:   translator,
		conntrack:    connTrack,
		loggerPrefix: &loggerPrefix,
	}
	return worker
}
