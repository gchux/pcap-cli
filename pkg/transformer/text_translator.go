package transformer

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
)

type (
	TextPcapTranslator struct {
		iface *PcapIface
	}

	textPcapTranslation struct {
		index   int // allows layers to be sorted on `String()` invocation
		builder *strings.Builder
	}

	textPcapTranslations map[int]*textPcapTranslation
)

func (tt *textPcapTranslation) String() string {
	return tt.builder.String()
}

func (tt *textPcapTranslations) String() string {
	keys := make([]int, 0)
	for key := range *tt {
		keys = append(keys, key)
	}
	// print layers in order
	sort.Ints(keys)
	var packetStr strings.Builder
	for _, key := range keys {
		builder := (*tt)[key].builder
		if key > 0 {
			packetStr.WriteString("\n - ")
		}
		packetStr.WriteString(builder.String())
	}
	return packetStr.String()
}

func (t *TextPcapTranslator) next(ctx context.Context, packet *gopacket.Packet, serial *uint64) fmt.Stringer {
	var text strings.Builder

	text.WriteString("[ctx=")
	text.WriteString(fmt.Sprintf("%s", ctx.Value(ContextID)))
	text.WriteString("|num=")
	text.WriteString(fmt.Sprintf("%d", *serial))
	text.WriteString("]")

	// `next` returns the container to be used for merging all layers
	return &textPcapTranslations{0: &textPcapTranslation{0, &text}}
}

func (t *TextPcapTranslator) asTranslation(buffer fmt.Stringer) *textPcapTranslation {
	return buffer.(*textPcapTranslation)
}

func (t *TextPcapTranslator) translateEthernetLayer(ctx context.Context, eth *layers.Ethernet) fmt.Stringer {
	var text strings.Builder

	text.WriteString("[L2|type=")
	text.WriteString(eth.EthernetType.String())
	text.WriteString("|")
	text.WriteString(fmt.Sprintf("src=%s", eth.SrcMAC.String()))
	text.WriteString("|")
	text.WriteString(fmt.Sprintf("dst=%s", eth.DstMAC.String()))
	text.WriteString("]")

	return &textPcapTranslation{1, &text}
}

func (t *TextPcapTranslator) translateIPv4Layer(ctx context.Context, ip4 *layers.IPv4) fmt.Stringer {
	// [TODO]: implement IPv4 layer translation
	return &textPcapTranslation{2, new(strings.Builder)}
}

func (t *TextPcapTranslator) translateIPv6Layer(ctx context.Context, ip6 *layers.IPv6) fmt.Stringer {
	// [TODO]: implement IPv6 layer translation
	return &textPcapTranslation{2, new(strings.Builder)}
}

func (t *TextPcapTranslator) translateUDPLayer(ctx context.Context, udp *layers.UDP) fmt.Stringer {
	// [TODO]: implement UDP layer translation
	return &textPcapTranslation{3, new(strings.Builder)}
}

func (t *TextPcapTranslator) translateTCPLayer(ctx context.Context, tcp *layers.TCP) fmt.Stringer {
	// [TODO]: implement TCP layer translation
	return &textPcapTranslation{3, new(strings.Builder)}
}

func (t *TextPcapTranslator) translateTLSLayer(ctx context.Context, tls *layers.TLS) fmt.Stringer {
	// [TODO]: implement TLS layer translation
	return &textPcapTranslation{4, new(strings.Builder)}
}

func (t *TextPcapTranslator) translateDNSLayer(ctx context.Context, dns *layers.DNS) fmt.Stringer {
	// [TODO]: implement DNS layer translation
	return &textPcapTranslation{4, new(strings.Builder)}
}

func (t *TextPcapTranslator) merge(ctx context.Context, tgt fmt.Stringer, src fmt.Stringer) (fmt.Stringer, error) {
	srcTranslation := t.asTranslation(src)
	switch typedObj := tgt.(type) {
	case *textPcapTranslations:
		// add reference to another layer translation
		(*typedObj)[srcTranslation.index] = srcTranslation
	case *textPcapTranslation:
		// 1st `merge` invocation might not actually be a map (`textPcapTranslations`)
		// do not be confused: this is a `map[int]*textPcapTranslation`
		tgt = &textPcapTranslations{
			typedObj.index:       typedObj,
			srcTranslation.index: srcTranslation,
		}
	}
	return tgt, nil
}

func (t *TextPcapTranslator) finalize(ctx context.Context, packet fmt.Stringer) (fmt.Stringer, error) {
	return packet, nil
}

func (t *TextPcapTranslator) write(ctx context.Context, writer io.Writer, packet *fmt.Stringer) (int, error) {
	translation := t.asTranslation(*packet)
	_, err := translation.builder.WriteString("\n")
	if err != nil {
		return 0, errors.Wrap(err, "TEXT translation failed")
	}
	return fmt.Fprint(writer, translation.String())
}

func newTextPcapTranslator(iface *PcapIface) *TextPcapTranslator {
	return &TextPcapTranslator{iface: iface}
}

// [TODO]: remove samples when all layers translations are implemented
func (t *TextPcapTranslator) translate(packet *gopacket.Packet) error {
	p := *packet

	// Iterate over all layers, printing out each layer type
	fmt.Println("All packet layers:")
	for _, layer := range p.Layers() {
		fmt.Println("- ", layer.LayerType())
	}

	// Check for errors
	if err := p.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
	return nil
}
