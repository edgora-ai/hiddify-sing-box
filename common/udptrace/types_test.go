package udptrace

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestUDPTraceSelectorValidation(t *testing.T) {
	invalid := []struct {
		name   string
		change func(*Selector)
	}{
		{"missing network", func(s *Selector) { s.Network = "" }},
		{"case sensitive network", func(s *Selector) { s.Network = "UDP" }},
		{"other network", func(s *Selector) { s.Network = "tcp" }},
		{"missing source", func(s *Selector) { s.SourcePort = 0 }},
		{"missing destination", func(s *Selector) { s.Destination = netip.AddrPort{} }},
		{"missing destination port", func(s *Selector) { s.Destination = netip.AddrPortFrom(netip.MustParseAddr("192.0.2.7"), 0) }},
		{"zone", func(s *Selector) { s.Destination = netip.MustParseAddrPort("[fe80::1%en0]:3478") }},
		{"missing outbound", func(s *Selector) { s.Outbound = "" }},
		{"oversized outbound", func(s *Selector) { s.Outbound = strings.Repeat("x", MaxTagBytes+1) }},
		{"invalid UTF8 outbound", func(s *Selector) { s.Outbound = string([]byte{0xff}) }},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			selector := testSelector()
			test.change(&selector)
			if !errors.Is(selector.Validate(), ErrInvalidSelector) {
				t.Fatal("invalid selector was accepted")
			}
		})
	}
	for _, address := range []string{"192.0.2.7:1", "[::ffff:192.0.2.7]:65535", "[2001:db8::1]:3478"} {
		selector := testSelector()
		selector.Destination = netip.MustParseAddrPort(address)
		selector.Outbound = strings.Repeat("é", MaxTagBytes/2)
		if err := selector.Validate(); err != nil {
			t.Fatal("valid literal selector was rejected:", err)
		}
	}
}

func TestUDPTraceClosedEnumValidation(t *testing.T) {
	stages := []Stage{StageClaimed, StageAcquireEnter, StageAcquireReturn, StageBackendEnter, StageBackendReturn,
		StageObjectCreated, StagePacketReadEnter, StagePacketReadReturn, StagePacketWriteEnter, StagePacketWriteReturn,
		StageDecodedReadEnter, StageDecodedReadReturn, StageDecodedReadError, StageClose, StageUnsupported}
	var seen uint32
	for _, stage := range stages {
		bit := stage.bit()
		if bit == 0 || seen&bit != 0 {
			t.Fatalf("invalid or reused stage bit: %q", stage)
		}
		seen |= bit
	}
	if Stage("").bit() != 0 || Stage("unlisted").bit() != 0 {
		t.Fatal("open-ended stage accepted")
	}
	for _, kind := range []ErrorKind{"", ErrorNone, ErrorEOF, ErrorUnexpectedEOF, ErrorCanceled, ErrorDeadline, ErrorClosed, ErrorTimeout, ErrorOther} {
		if !kind.valid() {
			t.Fatalf("error kind rejected: %q", kind)
		}
	}
	for _, kind := range []BackendKind{"", BackendTransport, BackendTLS, BackendTCP} {
		if !kind.valid() {
			t.Fatalf("backend kind rejected: %q", kind)
		}
	}
	for _, kind := range []UnsupportedKind{"", UnsupportedUDPConnect, UnsupportedMultiplex, UnsupportedEncoding, UnsupportedType, UnsupportedCapabilities} {
		if !kind.valid() {
			t.Fatalf("unsupported kind rejected: %q", kind)
		}
	}
	if ErrorKind("unlisted").valid() || BackendKind("unlisted").valid() || UnsupportedKind("unlisted").valid() {
		t.Fatal("open-ended detail enum accepted")
	}
}

func TestUDPTraceHeaderValidation(t *testing.T) {
	for _, status := range []HeaderStatus{HeaderNew, HeaderKeep, HeaderEnd, HeaderKeepAlive, HeaderOther} {
		for _, length := range []HeaderLength{HeaderLengthShort, HeaderLengthFour, HeaderLengthLong} {
			summary := HeaderSummary{State: HeaderComplete, CapturedBytes: PrefixBytes, Decoded: &HeaderFields{Status: status, Length: length}}
			if !summary.valid() {
				t.Fatalf("closed summary enum rejected: %+v", summary)
			}
		}
	}
	invalid := []HeaderSummary{
		{},
		{State: HeaderState("private-state-sentinel")},
		{State: HeaderWaiting, CapturedBytes: -1},
		{State: HeaderWaiting, CapturedBytes: PrefixBytes + 1},
		{State: HeaderWaiting, Decoded: &HeaderFields{Status: HeaderNew, Length: HeaderLengthFour}},
		{State: HeaderUnknownConcurrent, Decoded: &HeaderFields{Status: HeaderNew, Length: HeaderLengthFour}},
		{State: HeaderComplete, CapturedBytes: PrefixBytes},
		{State: HeaderComplete, CapturedBytes: PrefixBytes - 1, Decoded: &HeaderFields{Status: HeaderNew, Length: HeaderLengthFour}},
		{State: HeaderComplete, CapturedBytes: PrefixBytes + 1, Decoded: &HeaderFields{Status: HeaderNew, Length: HeaderLengthFour}},
		{State: HeaderComplete, CapturedBytes: PrefixBytes, Decoded: &HeaderFields{Status: HeaderStatus("private-status-sentinel"), Length: HeaderLengthFour}},
		{State: HeaderComplete, CapturedBytes: PrefixBytes, Decoded: &HeaderFields{Status: HeaderNew, Length: HeaderLength("private-length-sentinel")}},
		{State: HeaderComplete, CapturedBytes: PrefixBytes, Decoded: &HeaderFields{}},
	}
	manager := testManager(t)
	trace := claimManager(t, manager)
	for i, summary := range invalid {
		if summary.valid() {
			t.Fatalf("invalid header %d accepted", i)
		}
		trace.SetHeader(summary)
	}
	if snapshotOf(t, manager).Header != (HeaderSummary{State: HeaderWaiting}) {
		t.Fatal("invalid header mutated recorder")
	}
	for count := 0; count <= PrefixBytes; count++ {
		trace.SetHeader(HeaderSummary{State: HeaderWaiting, CapturedBytes: count})
		if snapshotOf(t, manager).Header.CapturedBytes != count {
			t.Fatal("valid bounded progress was not retained")
		}
	}
}

func TestUDPTraceByteFactEncoding(t *testing.T) {
	cases := []struct {
		detail Detail
		want   string
	}{
		{Detail{Error: ErrorNone}, `{"error":"none"}`},
		{Detail{Error: ErrorNone, Bytes: 999}, `{"error":"none"}`},
		{Detail{Error: ErrorNone, HasBytes: true}, `{"error":"none","bytes":0,"has_bytes":true}`},
		{Detail{Bytes: 6, HasBytes: true}, `{"bytes":6,"has_bytes":true}`},
	}
	for _, test := range cases {
		encoded, err := json.Marshal(test.detail)
		if err != nil || string(encoded) != test.want {
			t.Fatalf("byte fact encoding = %s, error %v; want %s", encoded, err, test.want)
		}
		var readBack Detail
		if err := json.Unmarshal(encoded, &readBack); err != nil {
			t.Fatal(err)
		}
		if readBack.HasBytes != test.detail.HasBytes || readBack.HasBytes && readBack.Bytes != test.detail.Bytes {
			t.Fatal("byte fact did not survive readback")
		}
	}
}

func TestUDPTraceEntropyFailureIsUnavailable(t *testing.T) {
	manager, err := newManager(strings.NewReader("short"))
	if manager != nil || !errors.Is(err, ErrDisabled) {
		t.Fatal("entropy failure did not return an unavailable manager")
	}
	manager.Close()
}
