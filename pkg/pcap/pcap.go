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

package pcap

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gchux/pcap-cli/pkg/transformer"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/wissance/stringFormatter"
)

type (
	PcapFilterMode uint8

	PcapFilter struct {
		Raw *string
	}

	PcapFilterProvider interface {
		fmt.Stringer
		Get(context.Context) (*string, bool)
		Apply(context.Context, *string, PcapFilterMode) *string
	}

	PcapEmphemeralPorts = transformer.PcapEmphemeralPorts

	PcapConfig struct {
		Debug      bool
		Promisc    bool
		Iface      string
		Snaplen    int
		TsType     string
		Format     string
		Filter     string
		Output     string
		Interval   int
		Extension  string
		Ordered    bool
		ConnTrack  bool
		Device     *PcapDevice
		Filters    []PcapFilterProvider
		Ephemerals *PcapEmphemeralPorts
	}

	PcapEngine interface {
		Start(context.Context, []PcapWriter, <-chan *time.Duration) error
		IsActive() bool
	}

	PcapDevice struct {
		NetInterface *net.Interface
		pcap.Interface
	}

	Pcap struct {
		config         *PcapConfig
		isActive       *atomic.Bool
		activeHandle   gopacket.PacketDataSource
		inactiveHandle *pcap.InactiveHandle
		fn             transformer.IPcapTransformer
	}

	Tcpdump struct {
		config   *PcapConfig
		isActive *atomic.Bool
		tcpdump  string
	}
)

const (
	PCAP_FILTER_MODE_AND PcapFilterMode = iota
	PCAP_FILTER_MODE_OR
)

const (
	PcapContextID      = transformer.ContextID
	PcapContextLogName = transformer.ContextLogName
)

const (
	PcapDefaultFilter = "(tcp or udp or icmp or icmp6) and (ip or ip6)"
)

const (
	pcap_min_ephemeral_port uint16 = 0x0400 // 1024 – start of registered ports per RFC 6056
	PCAP_MIN_EPHEMERAL_PORT uint16 = 0x8000 // 32768 – preferred MIN ephemeral port ( not as high as 0x0C000 / 49152 )
	PCAP_MAX_EPHEMERAL_PORT uint16 = 0xFFFF // 65535 ( Linux: 60999 / 0xEE47 )
)

const (
	// see: https://github.com/google/gopacket/blob/master/pcap/pcap.go#L802-L808
	any_device_name  string = "any"
	any_devide_index uint8  = 0
)

func providePcapFilter(
	ctx context.Context,
	filter *string,
	providers []PcapFilterProvider,
) *string {
	select {
	case <-ctx.Done():
		return filter
	default:
	}

	pcapFilter := ""

	// if `filter` is available, then providers are not used to build the BPF filter.
	if filter != nil && *filter != "" && !strings.EqualFold(*filter, "DISABLED") {
		// `filter` is extremely unsafe as it is a free form expression:
		// [ToDo] – validate `filter` to enforce correctness of expressions.
		pcapFilter = stringFormatter.Format("({0})", *filter)
	} else if len(providers) > 0 {
		for _, provider := range providers {
			if provider != nil {
				if f := provider.Apply(ctx,
					&pcapFilter, PCAP_FILTER_MODE_AND); f != nil {
					pcapFilter = *f
				}
			}
		}
	} else {
		pcapFilter = string(PcapDefaultFilter)
	}

	return &pcapFilter
}

func findAllDevs(compare func(*string) bool) ([]*PcapDevice, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	var devs []*PcapDevice

	for _, device := range devices {
		if compare(&device.Name) {
			iface, err := net.InterfaceByName(device.Name)
			if err != nil {
				continue
			}
			devs = append(devs, &PcapDevice{iface, device})
		}
	}

	return devs, nil
}

func FindDevicesByRegex(exp *regexp.Regexp) ([]*PcapDevice, error) {
	compare := func(deviceName *string) bool {
		return exp.MatchString(*deviceName)
	}
	return findAllDevs(compare)
}

func FindDevicesByName(deviceName *string) ([]*PcapDevice, error) {
	name := *deviceName
	compare := func(deviceName *string) bool {
		return name == *deviceName
	}
	return findAllDevs(compare)
}
