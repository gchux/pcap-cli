package transformer

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/Jeffail/gabs/v2"
	"github.com/google/gopacket/layers"
	"golang.org/x/crypto/cryptobyte"
)

func (t *JSONPcapTranslator) translateTLSLayer_decodeClientHello(hs cryptobyte.String, json *gabs.Container) {
	ch := gabs.New()
	ch.Set("ClientHello", "type")

	var clientHello cryptobyte.String
	hs.ReadUint24LengthPrefixed(&clientHello)

	var legacyVersion uint16
	clientHello.ReadUint16(&legacyVersion)
	ch.Set(layers.TLSVersion(legacyVersion).String(), "legacy_version")

	// var random []byte
	// clientHello.ReadBytes(&random, 32)
	// ch.Set(random, "random")

	// var legacySessionID []byte
	// clientHello.ReadUint8LengthPrefixed((*cryptobyte.String)(&legacySessionID))
	// ch.Set(legacySessionID, "legacy_session_id")

	clientHello.Skip(33)

	var ciphersuitesBytes cryptobyte.String
	clientHello.ReadUint16LengthPrefixed(&ciphersuitesBytes)
	for !ciphersuitesBytes.Empty() {
		var ciphersuite uint16
		ciphersuitesBytes.ReadUint16(&ciphersuite)
		ch.ArrayAppendP(ciphersuite, "cipherSuites")
	}

	var legacyCompressionMethods []uint8
	clientHello.ReadUint8LengthPrefixed((*cryptobyte.String)(&legacyCompressionMethods))
	ch.Set(legacyCompressionMethods, "legacy_compression_methods")

	var extensionsBytes cryptobyte.String
	clientHello.ReadUint16LengthPrefixed(&extensionsBytes)
	ch.Array("extensions")
	for !extensionsBytes.Empty() {
		var extType uint16
		extensionsBytes.ReadUint16(&extType)

		ext := gabs.New()
		ext.Set(extType, "type")

		var extData cryptobyte.String
		extensionsBytes.ReadUint16LengthPrefixed(&extData)

		switch extType {
		default:
			ext.Set("UNKNOWN", "name")
		case 0: // Server Name
			ext.Set("server_name", "name")
			extData.Skip(5)
			ext.Set(string(extData), "data")
		case 16: // ALPN
			ext.Set("application_layer_protocol_negotiation", "name")
			var alpnData cryptobyte.String
			extData.ReadUint16LengthPrefixed(&alpnData)
			for !alpnData.Empty() {
				var length uint8
				alpnData.ReadUint8(&length)
				var proto []byte
				alpnData.ReadBytes(&proto, int(length))
				ext.ArrayAppend(string(proto), "data")
			}
		}

		ch.ArrayAppend(ext, "extensions")
	}

	json.ArrayAppendP(ch, "TLS.data")
}

func (t *JSONPcapTranslator) decodeTLSRecords(it uint8, data []byte, json *gabs.Container) error {
	if len(data) < 5 {
		return errors.New("TLS record too short")
	}

	var h layers.TLSRecordHeader
	h.ContentType = layers.TLSType(data[0])
	h.Version = layers.TLSVersion(binary.BigEndian.Uint16(data[1:3]))
	h.Length = binary.BigEndian.Uint16(data[3:5])

	if h.ContentType.String() == "Unknown" {
		return errors.New("Unknown TLS record type")
	}

	hl := 5 // header length
	tl := hl + int(h.Length)

	if len(data) < tl {
		return errors.New("TLS packet length mismatch")
	}

	switch h.ContentType {
	default:
		return errors.New("unknown TLS record type")
	case layers.TLSChangeCipherSpec, layers.TLSAlert, layers.TLSHandshake:
		b := data[hl:tl]
		hs := cryptobyte.String(b)
		var messageType uint8
		if !hs.ReadUint8(&messageType) {
			return errors.New("failed to decode TLS layer")
		}
		// `ClientHello` and `ApplicationData` are the only full layers we have access to;
		// see: https://github.com/google/gopacket/blob/v1.1.19/layers/tls.go#L136-L139
		// reason: when `gopacket` decodes `TLS`, it repaces content by the last layer parsed
		if messageType == 1 {
			t.translateTLSLayer_decodeClientHello(hs, json)
		}
	case layers.TLSApplicationData:
	}

	if len(data) == tl {
		return nil
	}
	return t.decodeTLSRecords(it+1, data[tl:], json)
}

func (t *JSONPcapTranslator) translateTLSLayer_RecordHeader(ctx context.Context, json *gabs.Container, recordHeader layers.TLSRecordHeader) {
	json.SetP(recordHeader.Version.String(), "version")
	json.SetP(recordHeader.ContentType.String(), "content_type")
	json.SetP(recordHeader.Length, "length")
}

func (t *JSONPcapTranslator) translateTLSLayer_ChangeCipherSpec(ctx context.Context, json *gabs.Container, tls *layers.TLS) {
	json.ArrayP("TLS.change_cipher_spec")
	for _, changeCipherSpec := range tls.ChangeCipherSpec {
		o := gabs.New()
		t.translateTLSLayer_RecordHeader(ctx, o, changeCipherSpec.TLSRecordHeader)
		o.SetP(changeCipherSpec.Message.String(), "message")
		json.ArrayAppendP(o, "TLS.change_cipher_spec")
	}
}

func (t *JSONPcapTranslator) translateTLSLayer_Handshake(ctx context.Context, json *gabs.Container, tls *layers.TLS) {
	json.ArrayP("TLS.handshake")
	for _, handshake := range tls.Handshake {
		o := gabs.New()
		t.translateTLSLayer_RecordHeader(ctx, o, handshake.TLSRecordHeader)
		json.ArrayAppendP(o, "TLS.handshake")
	}
}

func (t *JSONPcapTranslator) translateTLSLayer_AppData(ctx context.Context, json *gabs.Container, tls *layers.TLS) {
	json.ArrayP("TLS.app_data")
	for _, appData := range tls.AppData {
		o := gabs.New()
		t.translateTLSLayer_RecordHeader(ctx, o, appData.TLSRecordHeader)
		json.ArrayAppendP(o, "TLS.app_data")
	}
}
