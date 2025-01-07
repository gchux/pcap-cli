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

	packetLayerTranslator = func(context.Context, *pcapTranslatorWorker, bool) fmt.Stringer

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
		// [0]: L2
		{
			// [0][0]
			func(ctx context.Context, w *pcapTranslatorWorker, deep bool) fmt.Stringer {
				return w.translateEthernetLayer(ctx, deep)
			},
		},

		// [1]: L3
		{
			// [1][0]
			func(ctx context.Context, w *pcapTranslatorWorker, deep bool) fmt.Stringer {
				return w.translateIPv4Layer(ctx, deep)
			},
			// [1][1]
			func(ctx context.Context, w *pcapTranslatorWorker, deep bool) fmt.Stringer {
				return w.translateIPv6Layer(ctx, deep)
			},
		},

		// [2]: L4
		{
			// ICMP layers
			//   - ICMP is not a transport layer protocol, but if it is present
			//   - then actual transport layer protocol translations are disabled;
			//   - thus, TCP/UDP translations are causally dependant on the lack of ICMP.

			// [2][0]
			func(ctx context.Context, w *pcapTranslatorWorker, deep bool) fmt.Stringer {
				return w.translateICMPv4Layer(ctx, deep)
			},
			// [2][1]
			func(ctx context.Context, w *pcapTranslatorWorker, deep bool) fmt.Stringer {
				return w.translateICMPv6Layer(ctx, deep)
			},

			// non-ICMP layers

			// [2][2]
			func(ctx context.Context, w *pcapTranslatorWorker, deep bool) fmt.Stringer {
				return w.translateTCPLayer(ctx, deep)
			},
			// [2][3]
			func(ctx context.Context, w *pcapTranslatorWorker, deep bool) fmt.Stringer {
				return w.translateUDPLayer(ctx, deep)
			},
		},

		// [3]: L7
		{
			// [3][0]
			func(ctx context.Context, w *pcapTranslatorWorker, deep bool) fmt.Stringer {
				return w.translateDNSLayer(ctx, deep)
			},
			// [3][1]
			func(ctx context.Context, w *pcapTranslatorWorker, deep bool) fmt.Stringer {
				return w.translateTLSLayer(ctx, deep)
			},
		},
	}

	packetLayerTranslatorsSize = len(packetLayerTranslators)

	packetLayerTranslatorsMap = map[gopacket.LayerType]packetLayerTranslator{
		layers.LayerTypeEthernet: packetLayerTranslators[0][0],
		layers.LayerTypeIPv4:     packetLayerTranslators[1][0],
		layers.LayerTypeIPv6:     packetLayerTranslators[1][1],
		layers.LayerTypeICMPv4:   packetLayerTranslators[2][0],
		layers.LayerTypeICMPv6:   packetLayerTranslators[2][1],
		layers.LayerTypeTCP:      packetLayerTranslators[2][2],
		layers.LayerTypeUDP:      packetLayerTranslators[2][3],
		layers.LayerTypeDNS:      packetLayerTranslators[3][0],
		layers.LayerTypeTLS:      packetLayerTranslators[3][1],
		layers.LayerTypeICMPv6Echo: func(
			ctx context.Context, w *pcapTranslatorWorker, deep bool,
		) fmt.Stringer {
			return w.translateICMPv6EchoLayer(ctx, deep)
		},
		layers.LayerTypeICMPv6Redirect: func(
			ctx context.Context, w *pcapTranslatorWorker, deep bool,
		) fmt.Stringer {
			return w.translateICMPv6RedirectLayer(ctx, deep)
		},
	}
)

func (w pcapTranslatorWorker) pkt(ctx context.Context) gopacket.Packet {
	return *w.packet
}

func (w *pcapTranslatorWorker) asLayer(ctx context.Context, layer gopacket.LayerType) gopacket.Layer {
	return w.pkt(ctx).Layer(layer)
}

func (w *pcapTranslatorWorker) translateLayer(
	ctx context.Context, layer gopacket.LayerType, deep bool,
) fmt.Stringer {
	// confirm that the packet actually contains the requested layer
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
	case *layers.ICMPv4:
		return w.translator.translateICMPv4Layer(ctx, lType)
	case *layers.ICMPv6:
		icmp6 := w.translator.translateICMPv6Layer(ctx, lType)

		// [ToDo]: handle layers.ICMPv6TypePacketTooBig
		if lType.TypeCode.Type() == layers.ICMPv6TypeDestinationUnreachable ||
			lType.TypeCode.Type() == layers.ICMPv6TypeTimeExceeded {
			return w.translator.translateICMPv6L3HeaderLayer(ctx, icmp6, lType)
		}

		if !deep {
			return icmp6
		}

		_l := w.asLayer(ctx, lType.NextLayerType())

		switch _lType := _l.(type) {
		default:
			return icmp6
		case *layers.ICMPv6Echo:
			return w.translator.translateICMPv6EchoLayer(ctx, icmp6, _lType)
		case *layers.ICMPv6Redirect:
			return w.translator.translateICMPv6RedirectLayer(ctx, icmp6, _lType)
		}
	case *layers.ICMPv6Echo:
		return w.translator.translateICMPv6EchoLayer(ctx, nil, lType)
	case *layers.ICMPv6Redirect:
		return w.translator.translateICMPv6RedirectLayer(ctx, nil, lType)
	case *layers.TCP:
		return w.translator.translateTCPLayer(ctx, lType)
	case *layers.UDP:
		return w.translator.translateUDPLayer(ctx, lType)
	case *layers.DNS:
		return w.translator.translateDNSLayer(ctx, lType)
	case *layers.TLS:
		return w.translator.translateTLSLayer(ctx, lType)
	}
}

func (w pcapTranslatorWorker) translateEthernetLayer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeEthernet, deep)
}

func (w *pcapTranslatorWorker) translateIPv4Layer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeIPv4, deep)
}

func (w *pcapTranslatorWorker) translateIPv6Layer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeIPv6, deep)
}

func (w *pcapTranslatorWorker) translateICMPv4Layer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeICMPv4, deep)
}

func (w *pcapTranslatorWorker) translateICMPv6Layer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeICMPv6, deep)
}

func (w *pcapTranslatorWorker) translateICMPv6EchoLayer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeICMPv6Echo, deep)
}

func (w *pcapTranslatorWorker) translateICMPv6RedirectLayer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeICMPv6Redirect, deep)
}

func (w *pcapTranslatorWorker) translateTCPLayer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeTCP, deep)
}

func (w *pcapTranslatorWorker) translateUDPLayer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeUDP, deep)
}

func (w *pcapTranslatorWorker) translateDNSLayer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeDNS, deep)
}

func (w *pcapTranslatorWorker) translateTLSLayer(ctx context.Context, deep bool) fmt.Stringer {
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

	return w.translateLayer(ctx, layers.LayerTypeTLS, deep)
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

	// number of layers to be translated
	packetLayers := w.pkt(ctx).Layers()
	wg.Add(len(packetLayers))
	// wg.Add(packetLayerTranslatorsSize)

	go func(wg *sync.WaitGroup) {
		wg.Wait()
		close(translations)
	}(&wg)

	// O(N); N is the number of layers available in the packet
	// this is a faster implementation as there is no layer discovery;
	// layers are translated on-demand based on the packet's contents.
	for i, l := range packetLayers {
		// translate layers concurrently:
		//   - layers must know nothing about each other
		go func(index int, layer gopacket.Layer, wg *sync.WaitGroup) {
			defer func(index int, layer gopacket.Layer, wg *sync.WaitGroup) {
				if r := recover(); r != nil {
					transformerLogger.Printf("%s @translator[%d][%s] | panic: %s\n%s\n",
						*w.loggerPrefix, index, layer.LayerType().String(), r, string(debug.Stack()))
					buffer = nil
				}
				wg.Done()
			}(index, layer, wg)

			if translator, ok := packetLayerTranslatorsMap[layer.LayerType()]; ok {
				if t := translator(ctx, w, false /* deep */); t != nil {
					translations <- t
				} else if layer.LayerType() != gopacket.LayerTypePayload {
					transformerLogger.Printf("%s @translator[%d][%s] | not found",
						*w.loggerPrefix, index, layer.LayerType().String())
				}
			}
		}(i, l, &wg)
	}

	// O(N*M)
	//   - N: layers
	//   - M: protocols
	/*
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
					if t := translator(ctx, w, true); t != nil {
						translations <- t
						break // skip next alternatives
					}
				}
			}(i, translators, &wg)
		}
	*/

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
