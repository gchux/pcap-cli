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
	"bytes"
	"net/netip"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/btree"
	"github.com/wissance/stringFormatter"
)

type (
	TCPFlag  string
	TCPFlags []uint8

	L3Proto uint8

	L4Proto uint8

	PcapL3Filters struct {
		// filter IPs in O(log N)
		networks4 *btree.BTreeG[netip.Prefix]
		networks6 *btree.BTreeG[netip.Prefix]
		protos    mapset.Set[uint8]
	}

	PcapL4Filters struct {
		// filter ports and flags in O(1)
		ports  mapset.Set[uint16]
		flags  uint8
		protos mapset.Set[uint8]
	}

	PcapFilters struct {
		l3 *PcapL3Filters
		l4 *PcapL4Filters
	}
)

func (flag *TCPFlag) materialize() uint8 {
	_flag := string(*flag)
	if f, ok := tcpFlags[_flag]; ok {
		return f
	}
	return uint8(tcpFlagNil)
}

func (flag *TCPFlag) ToUint8() uint8 {
	return flag.materialize()
}

func mergeTCPFlags(flags ...TCPFlag) uint8 {
	mergedFlags := uint8(0)
	for _, flag := range flags {
		mergedFlags |= flag.materialize()
	}
	return mergedFlags
}

func (f *PcapFilters) addNetwork(
	networks *btree.BTreeG[netip.Prefix],
	isIPv6 bool, ipRange string,
) {
	if prefix, err := netip.ParsePrefix(ipRange); err == nil {
		if isIPv6 && prefix.Addr().Is6() ||
			!isIPv6 && prefix.Addr().Is4() {
			networks.ReplaceOrInsert(prefix)
		}
	}
}

func (f *PcapFilters) addNetworks(
	networks *btree.BTreeG[netip.Prefix],
	isIPv6 bool, ipRanges ...string,
) {
	for _, ipRange := range ipRanges {
		f.addNetwork(networks, isIPv6, ipRange)
	}
}

func (f *PcapFilters) AddIPv4s(IPv4s ...string) {
	for _, IPv4 := range IPv4s {
		f.addNetwork(f.l3.networks4, false /* isIPv6 */, stringFormatter.Format("{0}/32", IPv4))
	}
}

func (f *PcapFilters) AddIPv6s(IPv6s ...string) {
	for _, IPv6 := range IPv6s {
		f.addNetwork(f.l3.networks4, false /* isIPv6 */, stringFormatter.Format("{0}/128", IPv6))
	}
}

func (f *PcapFilters) AddIPv4Ranges(IPv4Ranges ...string) {
	f.addNetworks(f.l3.networks4, false /* isIPv6 */, IPv4Ranges...)
}

func (f *PcapFilters) AddIPv6Ranges(IPv6Ranges ...string) {
	f.addNetworks(f.l3.networks6, true /* isIPv6 */, IPv6Ranges...)
}

func (f *PcapFilters) AddPorts(ports ...uint16) {
	f.l4.ports.Append(ports...)
}

func (f *PcapFilters) AddTCPFlags(flags ...TCPFlag) {
	for _, flag := range flags {
		f.l4.flags |= flag.materialize()
	}
}

func (f *PcapFilters) CombineAndAddTCPFlags(flag ...TCPFlag) {
	f.l4.flags |= mergeTCPFlags(flag...)
}

func (f *PcapFilters) AddProtos(
	protosSet mapset.Set[uint8],
	protos ...uint8,
) {
	for _, proto := range protos {
		protosSet.Add(proto)
	}
}

func (f *PcapFilters) AddL3Protos(protos ...uint8) {
	f.AddProtos(f.l3.protos, protos...)
}

func (f *PcapFilters) AddL4Protos(protos ...L4Proto) {
	for _, l4Proto := range protos {
		f.l4.protos.Add(uint8(l4Proto))
	}
}

func ipLessThanFunc(a, b netip.Prefix) bool {
	if a.Overlaps(b) {
		return false
	}
	return bytes.Compare(a.Addr().AsSlice(), b.Addr().AsSlice()) < 0
}

func NewPcapFilters() *PcapFilters {
	return &PcapFilters{
		l3: &PcapL3Filters{
			networks4: btree.NewG[netip.Prefix](2, ipLessThanFunc),
			networks6: btree.NewG[netip.Prefix](2, ipLessThanFunc),
			protos:    mapset.NewSet[uint8](),
		},
		l4: &PcapL4Filters{
			ports:  mapset.NewSet[uint16](),
			flags:  uint8(tcpFlagNil),
			protos: mapset.NewSet[uint8](),
		},
	}
}
