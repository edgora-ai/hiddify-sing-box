package route

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

const hSniffDNSInbound = "tun-test"

var hSniffDNSClient = netip.MustParseAddr("192.0.2.10")

type hSniffDNSClock struct {
	nanos atomic.Int64
}

func hNewSniffDNSCache(capacity int, maxTTL time.Duration) (*sniffDNSAssociations, *hSniffDNSClock) {
	clock := &hSniffDNSClock{}
	clock.nanos.Store(time.Date(2026, time.October, 15, 12, 0, 0, 0, time.UTC).UnixNano())
	return newSniffDNSAssociations(capacity, maxTTL, clock.now), clock
}

func (c *hSniffDNSClock) now() time.Time {
	return time.Unix(0, c.nanos.Load())
}

func (c *hSniffDNSClock) advance(duration time.Duration) {
	c.nanos.Add(int64(duration))
}

func hSniffDNSReply(domain string, queryType uint16, answers ...mDNS.RR) *mDNS.Msg {
	return &mDNS.Msg{
		MsgHdr: mDNS.MsgHdr{Response: true, Opcode: mDNS.OpcodeQuery, Rcode: mDNS.RcodeSuccess},
		Question: []mDNS.Question{{
			Name: domain, Qtype: queryType, Qclass: mDNS.ClassINET,
		}},
		Answer: answers,
	}
}

func hSniffDNSA(domain, address string, ttl uint32) *mDNS.A {
	return &mDNS.A{
		Hdr: mDNS.RR_Header{Name: domain, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: ttl},
		A:   net.ParseIP(address).To4(),
	}
}

func hSniffDNSAAAA(domain, address string, ttl uint32) *mDNS.AAAA {
	return &mDNS.AAAA{
		Hdr:  mDNS.RR_Header{Name: domain, Rrtype: mDNS.TypeAAAA, Class: mDNS.ClassINET, Ttl: ttl},
		AAAA: net.ParseIP(address).To16(),
	}
}

func hSniffDNSCNAME(domain, target string, ttl uint32) *mDNS.CNAME {
	return &mDNS.CNAME{
		Hdr:    mDNS.RR_Header{Name: domain, Rrtype: mDNS.TypeCNAME, Class: mDNS.ClassINET, Ttl: ttl},
		Target: target,
	}
}

func hAssertSniffDNSBounds(t *testing.T, cache *sniffDNSAssociations) {
	t.Helper()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	require.LessOrEqual(t, len(cache.entries), max(cache.capacity, 0))
	require.Equal(t, len(cache.entries), cache.lru.Len())
	count := 0
	for element := cache.lru.Front(); element != nil; element = element.Next() {
		entry := element.Value.(*sniffDNSAssociation)
		require.Same(t, element, cache.entries[entry.key])
		require.NotEmpty(t, entry.addresses)
		require.LessOrEqual(t, len(entry.addresses), sniffDNSMaxAddresses)
		count++
	}
	require.Equal(t, len(cache.entries), count)
}

func TestH_SniffDNSAssociationsSuccessfulAnswers(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name      string
		queryType uint16
		address   string
		answers   []mDNS.RR
	}{
		{
			name: "A", queryType: mDNS.TypeA, address: "203.0.113.10",
			answers: []mDNS.RR{hSniffDNSA("service.example.", "203.0.113.10", 60)},
		},
		{
			name: "AAAA", queryType: mDNS.TypeAAAA, address: "2001:db8::10",
			answers: []mDNS.RR{hSniffDNSAAAA("service.example.", "2001:db8::10", 60)},
		},
		{
			name: "CNAME A", queryType: mDNS.TypeA, address: "203.0.113.10",
			answers: []mDNS.RR{
				hSniffDNSCNAME("SERVICE.Example.", "CDN.Example.", 60),
				hSniffDNSA("cdn.example.", "203.0.113.10", 60),
			},
		},
		{
			name: "CNAME AAAA", queryType: mDNS.TypeAAAA, address: "2001:db8::10",
			answers: []mDNS.RR{
				hSniffDNSCNAME("service.example.", "cdn.example.", 60),
				hSniffDNSAAAA("cdn.example.", "2001:db8::10", 60),
			},
		},
		{
			name: "out of order multihop", queryType: mDNS.TypeA, address: "203.0.113.10",
			answers: []mDNS.RR{
				hSniffDNSA("edge.example.", "203.0.113.10", 60),
				hSniffDNSCNAME("cdn.example.", "edge.example.", 60),
				hSniffDNSCNAME("service.example.", "cdn.example.", 60),
			},
		},
		{
			name: "duplicate equivalent aliases", queryType: mDNS.TypeA, address: "203.0.113.10",
			answers: []mDNS.RR{
				hSniffDNSCNAME("service.example.", "CDN.EXAMPLE.", 60),
				hSniffDNSCNAME("SERVICE.EXAMPLE", "cdn.example", 30),
				hSniffDNSA("cdn.example.", "203.0.113.10", 60),
			},
		},
		{
			name: "A Go 16 byte representation", queryType: mDNS.TypeA, address: "203.0.113.10",
			answers: []mDNS.RR{&mDNS.A{
				Hdr: mDNS.RR_Header{Name: "service.example.", Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 60},
				A:   net.ParseIP("203.0.113.10"),
			}},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			cache, _ := hNewSniffDNSCache(8, time.Minute)
			address := netip.MustParseAddr(testCase.address)
			require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", address), "no DNS evidence")
			cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("SeRvIcE.Example.", testCase.queryType, testCase.answers...))
			require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", address))
			require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "SERVICE.EXAMPLE.", address))
			for _, notQueried := range []string{"cdn.example", "edge.example", "other.example", "example", "sub.service.example"} {
				require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, notQueried, address), notQueried)
			}
			require.Len(t, cache.entries, 1)
			hAssertSniffDNSBounds(t, cache)
		})
	}
}

func TestH_SniffDNSAssociationsClientAndSharedIPIsolation(t *testing.T) {
	t.Parallel()
	cache, _ := hNewSniffDNSCache(16, time.Minute)
	shared := netip.MustParseAddr("203.0.113.10")
	otherAddress := netip.MustParseAddr("203.0.113.20")
	otherClient := netip.MustParseAddr("192.0.2.20")
	cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("alpha.example.", mDNS.TypeA,
		hSniffDNSA("alpha.example.", shared.String(), 60)))
	require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "beta.example", shared))
	cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("beta.example.", mDNS.TypeA,
		hSniffDNSA("beta.example.", otherAddress.String(), 60)))
	require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "alpha.example", shared))
	require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "beta.example", shared), "no reverse-IP domain guessing")
	cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("beta.example.", mDNS.TypeA,
		hSniffDNSA("beta.example.", shared.String(), 60)))
	for _, domain := range []string{"alpha.example", "beta.example"} {
		require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, domain, shared))
		require.False(t, cache.matches(hSniffDNSInbound, otherClient, domain, shared))
		require.False(t, cache.matches("another-tun", hSniffDNSClient, domain, shared))
		require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, domain, otherAddress))
	}
	require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "unqueried.example", shared))
	cache.record("another-tun", hSniffDNSClient, hSniffDNSReply("alpha.example.", mDNS.TypeA,
		hSniffDNSA("alpha.example.", otherAddress.String(), 60)))
	cache.record(hSniffDNSInbound, otherClient, hSniffDNSReply("alpha.example.", mDNS.TypeA,
		hSniffDNSA("alpha.example.", otherAddress.String(), 60)))
	require.True(t, cache.matches("another-tun", hSniffDNSClient, "alpha.example", otherAddress))
	require.True(t, cache.matches(hSniffDNSInbound, otherClient, "alpha.example", otherAddress))
	require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "alpha.example", otherAddress))
	require.Len(t, cache.entries, 4)
	hAssertSniffDNSBounds(t, cache)
}

func TestH_SniffDNSAssociationsTTLs(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name    string
		maxTTL  time.Duration
		lives   time.Duration
		answers []mDNS.RR
	}{
		{"address", time.Hour, 5 * time.Second, []mDNS.RR{hSniffDNSA("service.example.", "203.0.113.10", 5)}},
		{"cap", 2 * time.Second, 2 * time.Second, []mDNS.RR{hSniffDNSA("service.example.", "203.0.113.10", 60)}},
		{"fractional cap", 1500 * time.Millisecond, 1500 * time.Millisecond, []mDNS.RR{hSniffDNSA("service.example.", "203.0.113.10", 60)}},
		{"CNAME minimum", time.Minute, 3 * time.Second, []mDNS.RR{
			hSniffDNSCNAME("service.example.", "cdn.example.", 3), hSniffDNSA("cdn.example.", "203.0.113.10", 60),
		}},
		{"multihop minimum", time.Minute, 2 * time.Second, []mDNS.RR{
			hSniffDNSCNAME("service.example.", "cdn.example.", 30),
			hSniffDNSCNAME("cdn.example.", "edge.example.", 2), hSniffDNSA("edge.example.", "203.0.113.10", 60),
		}},
		{"address below CNAME", time.Minute, time.Second, []mDNS.RR{
			hSniffDNSCNAME("service.example.", "cdn.example.", 30), hSniffDNSA("cdn.example.", "203.0.113.10", 1),
		}},
		{"cap below entire chain", time.Second, time.Second, []mDNS.RR{
			hSniffDNSCNAME("service.example.", "cdn.example.", 30), hSniffDNSA("cdn.example.", "203.0.113.10", 60),
		}},
		{"duplicate address minimum", time.Minute, 2 * time.Second, []mDNS.RR{
			hSniffDNSA("service.example.", "203.0.113.10", 60), hSniffDNSA("service.example.", "203.0.113.10", 2),
		}},
		{"duplicate alias minimum", time.Minute, 4 * time.Second, []mDNS.RR{
			hSniffDNSCNAME("service.example.", "cdn.example.", 60),
			hSniffDNSCNAME("service.example.", "cdn.example.", 4), hSniffDNSA("cdn.example.", "203.0.113.10", 60),
		}},
		{"largest legal TTL capped", time.Second, time.Second, []mDNS.RR{hSniffDNSA("service.example.", "203.0.113.10", 1<<31-1)}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			cache, clock := hNewSniffDNSCache(4, testCase.maxTTL)
			address := netip.MustParseAddr("203.0.113.10")
			cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("service.example.", mDNS.TypeA, testCase.answers...))
			key := sniffDNSAssociationKey{inbound: hSniffDNSInbound, client: hSniffDNSClient, domain: "service.example", queryType: mDNS.TypeA}
			require.Contains(t, cache.entries, key)
			stored := cache.entries[key].Value.(*sniffDNSAssociation)
			require.Equal(t, clock.now().Add(testCase.lives), stored.addresses[address], "verify stored expiry")
			require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", address))
			clock.advance(testCase.lives - time.Nanosecond)
			require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", address))
			clock.advance(time.Nanosecond)
			require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", address), "exact expiry; reads do not extend TTL")
			require.Empty(t, cache.entries)
			hAssertSniffDNSBounds(t, cache)
		})
	}
}

func TestH_SniffDNSAssociationsPerAddressExpiryAndZeroTTL(t *testing.T) {
	t.Parallel()
	cache, clock := hNewSniffDNSCache(4, time.Minute)
	cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("service.example.", mDNS.TypeA,
		hSniffDNSA("service.example.", "203.0.113.10", 1),
		hSniffDNSA("service.example.", "203.0.113.20", 3),
		hSniffDNSA("service.example.", "203.0.113.30", 0)))
	short := netip.MustParseAddr("203.0.113.10")
	long := netip.MustParseAddr("203.0.113.20")
	require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", short))
	require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", long))
	require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", netip.MustParseAddr("203.0.113.30")))
	clock.advance(time.Second)
	require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", short))
	require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", long))
	require.Len(t, cache.lru.Front().Value.(*sniffDNSAssociation).addresses, 1)
	clock.advance(2 * time.Second)
	require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", long))
	require.Empty(t, cache.entries)
	hAssertSniffDNSBounds(t, cache)
}

func TestH_SniffDNSAssociationsReplacementAndAddressFamilies(t *testing.T) {
	t.Parallel()
	cache, clock := hNewSniffDNSCache(4, time.Minute)
	old := netip.MustParseAddr("203.0.113.10")
	updated := netip.MustParseAddr("203.0.113.20")
	v6 := netip.MustParseAddr("2001:db8::10")
	cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("service.example.", mDNS.TypeA,
		hSniffDNSA("service.example.", old.String(), 60)))
	cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("service.example.", mDNS.TypeAAAA,
		hSniffDNSAAAA("service.example.", v6.String(), 30)))
	require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", old))
	require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", v6))
	clock.advance(10 * time.Second)
	cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("SERVICE.EXAMPLE.", mDNS.TypeA,
		hSniffDNSA("service.example.", updated.String(), 2)))
	require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", old))
	require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", updated))
	require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", v6))
	clock.advance(2 * time.Second)
	require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", updated))
	clock.advance(18 * time.Second)
	require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", v6), "retained AAAA did not get a fresh TTL")
	require.Empty(t, cache.entries)
	// A shorter replacement of the identical IP must shorten its authorization.
	cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("service.example.", mDNS.TypeA, hSniffDNSA("service.example.", old.String(), 60)))
	clock.advance(time.Second)
	cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("service.example.", mDNS.TypeA, hSniffDNSA("service.example.", old.String(), 1)))
	clock.advance(time.Second)
	require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", old))
	hAssertSniffDNSBounds(t, cache)
}

func TestH_SniffDNSAssociationsRejectAndRevoke(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name      string
		mutate    func(*mDNS.Msg) *mDNS.Msg
		keepPrior bool
	}{
		{"NODATA", func(m *mDNS.Msg) *mDNS.Msg { m.Answer = nil; return m }, false},
		{"NXDOMAIN with answers", func(m *mDNS.Msg) *mDNS.Msg { m.Rcode = mDNS.RcodeNameError; return m }, false},
		{"SERVFAIL", func(m *mDNS.Msg) *mDNS.Msg { m.Rcode = mDNS.RcodeServerFailure; return m }, false},
		{"REFUSED", func(m *mDNS.Msg) *mDNS.Msg { m.Rcode = mDNS.RcodeRefused; return m }, false},
		{"FORMERR", func(m *mDNS.Msg) *mDNS.Msg { m.Rcode = mDNS.RcodeFormatError; return m }, false},
		{"query not response", func(m *mDNS.Msg) *mDNS.Msg { m.Response = false; return m }, false},
		{"non QUERY opcode", func(m *mDNS.Msg) *mDNS.Msg { m.Opcode = mDNS.OpcodeNotify; return m }, false},
		{"truncated", func(m *mDNS.Msg) *mDNS.Msg { m.Truncated = true; return m }, false},
		{"reserved bit", func(m *mDNS.Msg) *mDNS.Msg { m.Zero = true; return m }, false},
		{"question class", func(m *mDNS.Msg) *mDNS.Msg { m.Question[0].Qclass = mDNS.ClassCHAOS; return m }, false},
		{"question TXT", func(m *mDNS.Msg) *mDNS.Msg { m.Question[0].Qtype = mDNS.TypeTXT; return m }, true},
		{"question ANY", func(m *mDNS.Msg) *mDNS.Msg { m.Question[0].Qtype = mDNS.TypeANY; return m }, true},
		{"wrong family", func(m *mDNS.Msg) *mDNS.Msg { m.Question[0].Qtype = mDNS.TypeAAAA; return m }, true},
		{"no question", func(m *mDNS.Msg) *mDNS.Msg { m.Question = nil; return m }, true},
		{"multiple questions", func(m *mDNS.Msg) *mDNS.Msg { m.Question = append(m.Question, m.Question[0]); return m }, true},
		{"malformed question", func(m *mDNS.Msg) *mDNS.Msg { m.Question[0].Name = "service.example.."; return m }, true},
		{"nil response", func(m *mDNS.Msg) *mDNS.Msg { return nil }, true},
		{"different question", func(m *mDNS.Msg) *mDNS.Msg { m.Question[0].Name = "different.example."; return m }, true},
		{"wrong owner", func(m *mDNS.Msg) *mDNS.Msg { m.Answer[0].(*mDNS.A).Hdr.Name = "unrelated.example."; return m }, false},
		{"malformed owner", func(m *mDNS.Msg) *mDNS.Msg { m.Answer[0].(*mDNS.A).Hdr.Name = "service..example."; return m }, false},
		{"answer class", func(m *mDNS.Msg) *mDNS.Msg { m.Answer[0].(*mDNS.A).Hdr.Class = mDNS.ClassCHAOS; return m }, false},
		{"answer header type", func(m *mDNS.Msg) *mDNS.Msg { m.Answer[0].(*mDNS.A).Hdr.Rrtype = mDNS.TypeAAAA; return m }, false},
		{"nil RR", func(m *mDNS.Msg) *mDNS.Msg { m.Answer = []mDNS.RR{nil}; return m }, false},
		{"typed nil A", func(m *mDNS.Msg) *mDNS.Msg { m.Answer = []mDNS.RR{(*mDNS.A)(nil)}; return m }, false},
		{"typed nil AAAA", func(m *mDNS.Msg) *mDNS.Msg { m.Answer = []mDNS.RR{(*mDNS.AAAA)(nil)}; return m }, false},
		{"typed nil CNAME", func(m *mDNS.Msg) *mDNS.Msg { m.Answer = []mDNS.RR{(*mDNS.CNAME)(nil)}; return m }, false},
		{"nil A data", func(m *mDNS.Msg) *mDNS.Msg { m.Answer[0].(*mDNS.A).A = nil; return m }, false},
		{"short A data", func(m *mDNS.Msg) *mDNS.Msg { m.Answer[0].(*mDNS.A).A = net.IP{1, 2, 3}; return m }, false},
		{"IPv6 in A", func(m *mDNS.Msg) *mDNS.Msg { m.Answer[0].(*mDNS.A).A = net.ParseIP("2001:db8::20"); return m }, false},
		{"IPv4 in AAAA", func(m *mDNS.Msg) *mDNS.Msg {
			m.Question[0].Qtype = mDNS.TypeAAAA
			m.Answer = []mDNS.RR{&mDNS.AAAA{Hdr: mDNS.RR_Header{Name: "service.example.", Class: mDNS.ClassINET, Rrtype: mDNS.TypeAAAA, Ttl: 60}, AAAA: net.IP{203, 0, 113, 20}}}
			return m
		}, true},
		{"mapped AAAA", func(m *mDNS.Msg) *mDNS.Msg {
			m.Question[0].Qtype = mDNS.TypeAAAA
			m.Answer = []mDNS.RR{hSniffDNSAAAA("service.example.", "::ffff:203.0.113.20", 60)}
			return m
		}, true},
		{"zero TTL", func(m *mDNS.Msg) *mDNS.Msg { m.Answer[0].(*mDNS.A).Hdr.Ttl = 0; return m }, false},
		{"high bit TTL", func(m *mDNS.Msg) *mDNS.Msg { m.Answer[0].(*mDNS.A).Hdr.Ttl = 1 << 31; return m }, false},
		{"max uint32 TTL", func(m *mDNS.Msg) *mDNS.Msg { m.Answer[0].(*mDNS.A).Hdr.Ttl = ^uint32(0); return m }, false},
		{"unspecified A", func(m *mDNS.Msg) *mDNS.Msg { m.Answer[0].(*mDNS.A).A = net.IPv4zero; return m }, false},
		{"multicast A", func(m *mDNS.Msg) *mDNS.Msg { m.Answer[0].(*mDNS.A).A = net.ParseIP("224.0.0.1"); return m }, false},
		{"Additional only", func(m *mDNS.Msg) *mDNS.Msg { m.Extra, m.Answer = m.Answer, nil; return m }, false},
		{"Authority only", func(m *mDNS.Msg) *mDNS.Msg { m.Ns, m.Answer = m.Answer, nil; return m }, false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			cache, _ := hNewSniffDNSCache(4, time.Minute)
			prior := netip.MustParseAddr("203.0.113.10")
			candidate := netip.MustParseAddr("203.0.113.20")
			cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("service.example.", mDNS.TypeA,
				hSniffDNSA("service.example.", prior.String(), 60)))
			require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", prior))
			invalid := testCase.mutate(hSniffDNSReply("service.example.", mDNS.TypeA,
				hSniffDNSA("service.example.", candidate.String(), 60)))
			cache.record(hSniffDNSInbound, hSniffDNSClient, invalid)
			require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", candidate))
			require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "different.example", candidate))
			require.Equal(t, testCase.keepPrior, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", prior))
			hAssertSniffDNSBounds(t, cache)
		})
	}
}

func TestH_SniffDNSAssociationsBadCNAMEChains(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name    string
		answers []mDNS.RR
	}{
		{"self loop", []mDNS.RR{hSniffDNSCNAME("service.example.", "SERVICE.EXAMPLE.", 60)}},
		{"two node cycle", []mDNS.RR{
			hSniffDNSCNAME("service.example.", "cdn.example.", 60), hSniffDNSCNAME("cdn.example.", "service.example.", 60),
		}},
		{"ambiguous targets", []mDNS.RR{
			hSniffDNSCNAME("service.example.", "cdn.example.", 60), hSniffDNSCNAME("service.example.", "other.example.", 60),
			hSniffDNSA("cdn.example.", "203.0.113.20", 60), hSniffDNSA("other.example.", "203.0.113.20", 60),
		}},
		{"CNAME and A at query", []mDNS.RR{
			hSniffDNSCNAME("service.example.", "cdn.example.", 60), hSniffDNSA("service.example.", "203.0.113.20", 60),
			hSniffDNSA("cdn.example.", "203.0.113.20", 60),
		}},
		{"CNAME and opposite family at query", []mDNS.RR{
			hSniffDNSCNAME("service.example.", "cdn.example.", 60), hSniffDNSAAAA("service.example.", "2001:db8::20", 60),
			hSniffDNSA("cdn.example.", "203.0.113.20", 60),
		}},
		{"address on intermediate alias", []mDNS.RR{
			hSniffDNSCNAME("service.example.", "cdn.example.", 60), hSniffDNSCNAME("cdn.example.", "edge.example.", 60),
			hSniffDNSA("cdn.example.", "203.0.113.20", 60), hSniffDNSA("edge.example.", "203.0.113.20", 60),
		}},
		{"missing terminal address", []mDNS.RR{
			hSniffDNSCNAME("service.example.", "cdn.example.", 60), hSniffDNSA("unrelated.example.", "203.0.113.20", 60),
		}},
		{"zero alias TTL", []mDNS.RR{
			hSniffDNSCNAME("service.example.", "cdn.example.", 0), hSniffDNSA("cdn.example.", "203.0.113.20", 60),
		}},
		{"high bit alias TTL", []mDNS.RR{
			hSniffDNSCNAME("service.example.", "cdn.example.", 1<<31), hSniffDNSA("cdn.example.", "203.0.113.20", 60),
		}},
		{"duplicate zero alias TTL", []mDNS.RR{
			hSniffDNSCNAME("service.example.", "cdn.example.", 60), hSniffDNSCNAME("service.example.", "cdn.example.", 0),
			hSniffDNSA("cdn.example.", "203.0.113.20", 60),
		}},
		{"malformed target", []mDNS.RR{
			hSniffDNSCNAME("service.example.", "cdn..example.", 60), hSniffDNSA("cdn.example.", "203.0.113.20", 60),
		}},
		{"wrong alias class", []mDNS.RR{&mDNS.CNAME{
			Hdr: mDNS.RR_Header{Name: "service.example.", Class: mDNS.ClassCHAOS, Rrtype: mDNS.TypeCNAME, Ttl: 60}, Target: "cdn.example.",
		}, hSniffDNSA("cdn.example.", "203.0.113.20", 60)}},
		{"wrong alias header type", []mDNS.RR{&mDNS.CNAME{
			Hdr: mDNS.RR_Header{Name: "service.example.", Class: mDNS.ClassINET, Rrtype: mDNS.TypeA, Ttl: 60}, Target: "cdn.example.",
		}, hSniffDNSA("cdn.example.", "203.0.113.20", 60)}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			cache, _ := hNewSniffDNSCache(4, time.Minute)
			prior := netip.MustParseAddr("203.0.113.10")
			cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("service.example.", mDNS.TypeA, hSniffDNSA("service.example.", prior.String(), 60)))
			cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("service.example.", mDNS.TypeA, testCase.answers...))
			require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", prior))
			require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", netip.MustParseAddr("203.0.113.20")))
			require.Empty(t, cache.entries)
			hAssertSniffDNSBounds(t, cache)
		})
	}
}

func TestH_SniffDNSAssociationsIgnoreUnrelatedRecords(t *testing.T) {
	t.Parallel()
	cache, _ := hNewSniffDNSCache(4, time.Minute)
	response := hSniffDNSReply("service.example.", mDNS.TypeA,
		hSniffDNSCNAME("service.example.", "cdn.example.", 60),
		hSniffDNSA("cdn.example.", "203.0.113.10", 60),
		hSniffDNSA("unrelated.example.", "203.0.113.20", 60),
		&mDNS.TXT{Hdr: mDNS.RR_Header{Name: "service.example.", Rrtype: mDNS.TypeTXT, Class: mDNS.ClassINET}, Txt: []string{"203.0.113.20"}},
		&mDNS.RRSIG{Hdr: mDNS.RR_Header{Name: "cdn.example.", Rrtype: mDNS.TypeRRSIG, Class: mDNS.ClassINET}})
	response.Extra = []mDNS.RR{
		nil,
		hSniffDNSCNAME("service.example.", "attacker.example.", 60),
		hSniffDNSCNAME("cdn.example.", "service.example.", 60),
		hSniffDNSA("attacker.example.", "203.0.113.20", 60),
		hSniffDNSA("cdn.example.", "203.0.113.20", 60),
	}
	response.Ns = []mDNS.RR{hSniffDNSA("cdn.example.", "203.0.113.20", 60)}
	cache.record(hSniffDNSInbound, hSniffDNSClient, response)
	require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", netip.MustParseAddr("203.0.113.10")))
	require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", netip.MustParseAddr("203.0.113.20")))
	require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "cdn.example", netip.MustParseAddr("203.0.113.10")))
	hAssertSniffDNSBounds(t, cache)
	cache.clear()
	// A chain ending only in Additional is not an answer, even for the right owner.
	response.Answer = []mDNS.RR{hSniffDNSCNAME("service.example.", "cdn.example.", 60)}
	cache.record(hSniffDNSInbound, hSniffDNSClient, response)
	require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", netip.MustParseAddr("203.0.113.20")))
	require.Empty(t, cache.entries)
}

func TestH_SniffDNSAssociationsZeroTTLReplacement(t *testing.T) {
	t.Parallel()
	for _, zeroFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(zeroFirst), func(t *testing.T) {
			t.Parallel()
			cache, _ := hNewSniffDNSCache(4, time.Minute)
			old := netip.MustParseAddr("203.0.113.10")
			cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("service.example.", mDNS.TypeA, hSniffDNSA("service.example.", old.String(), 60)))
			duplicates := []mDNS.RR{hSniffDNSA("service.example.", old.String(), 60), hSniffDNSA("service.example.", old.String(), 0)}
			if zeroFirst {
				duplicates[0], duplicates[1] = duplicates[1], duplicates[0]
			}
			cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("service.example.", mDNS.TypeA, duplicates...))
			require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", old))
			require.Empty(t, cache.entries)
			hAssertSniffDNSBounds(t, cache)
		})
	}
}

func TestH_SniffDNSAssociationsNegativeRevokesQueryTypeAndNXDomain(t *testing.T) {
	t.Parallel()
	for _, rcode := range []int{mDNS.RcodeSuccess, mDNS.RcodeNameError, mDNS.RcodeServerFailure} {
		t.Run(mDNS.RcodeToString[rcode], func(t *testing.T) {
			t.Parallel()
			cache, _ := hNewSniffDNSCache(8, time.Minute)
			v4 := netip.MustParseAddr("203.0.113.10")
			v6 := netip.MustParseAddr("2001:db8::10")
			for _, client := range []netip.Addr{hSniffDNSClient, netip.MustParseAddr("192.0.2.20")} {
				cache.record(hSniffDNSInbound, client, hSniffDNSReply("service.example.", mDNS.TypeA, hSniffDNSA("service.example.", v4.String(), 60)))
				cache.record(hSniffDNSInbound, client, hSniffDNSReply("service.example.", mDNS.TypeAAAA, hSniffDNSAAAA("service.example.", v6.String(), 60)))
			}
			negative := hSniffDNSReply("service.example.", mDNS.TypeAAAA)
			negative.Rcode = rcode
			cache.record(hSniffDNSInbound, hSniffDNSClient, negative)
			require.Equal(t, rcode != mDNS.RcodeNameError, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", v4), "NODATA/errors preserve the other family; NXDOMAIN does not")
			require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", v6))
			for _, address := range []netip.Addr{v4, v6} {
				require.True(t, cache.matches(hSniffDNSInbound, netip.MustParseAddr("192.0.2.20"), "service.example", address))
			}
			hAssertSniffDNSBounds(t, cache)
		})
	}
}

func TestH_SniffDNSAssociationsClearAndLRU(t *testing.T) {
	t.Parallel()
	cache, _ := hNewSniffDNSCache(2, time.Minute)
	address := netip.MustParseAddr("203.0.113.10")
	record := func(domain string) {
		cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply(domain, mDNS.TypeA, hSniffDNSA(domain, address.String(), 60)))
		hAssertSniffDNSBounds(t, cache)
	}
	matched := func(domain string) bool {
		return cache.matches(hSniffDNSInbound, hSniffDNSClient, domain, address)
	}
	record("a.example")
	record("b.example")
	require.True(t, matched("a.example"), "successful reads refresh recency")
	require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "b.example", netip.MustParseAddr("203.0.113.20")))
	require.False(t, matched("absent.example"))
	record("c.example")
	require.False(t, matched("b.example"), "misses do not refresh recency")
	require.True(t, matched("a.example"))
	require.True(t, matched("c.example"))
	record("a.example")
	record("d.example")
	require.False(t, matched("c.example"), "replacement refreshes recency")
	require.True(t, matched("a.example"))
	require.True(t, matched("d.example"))
	cache.clear()
	require.False(t, matched("a.example"))
	require.False(t, matched("d.example"))
	require.Empty(t, cache.entries)
	hAssertSniffDNSBounds(t, cache)
	cache.clear()
	record("fresh.example")
	require.True(t, matched("fresh.example"))
	for index := 0; index < 100; index++ {
		record(fmt.Sprintf("host-%d.example", index))
	}
	require.Len(t, cache.entries, 2)
	require.True(t, matched("host-98.example"))
	require.True(t, matched("host-99.example"))
	require.False(t, matched("fresh.example"))
}

func TestH_SniffDNSAssociationsBounds(t *testing.T) {
	t.Parallel()
	for _, count := range []int{16, 17} {
		t.Run(fmt.Sprintf("aliases-%d", count), func(t *testing.T) {
			t.Parallel()
			cache, _ := hNewSniffDNSCache(4, time.Minute)
			var answer []mDNS.RR
			for index := 0; index < count; index++ {
				answer = append(answer, hSniffDNSCNAME(fmt.Sprintf("alias-%d.example.", index), fmt.Sprintf("alias-%d.example.", index+1), 60))
			}
			answer = append(answer, hSniffDNSA(fmt.Sprintf("alias-%d.example.", count), "203.0.113.10", 60))
			cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("alias-0.example.", mDNS.TypeA, answer...))
			require.Equal(t, count == 16, cache.matches(hSniffDNSInbound, hSniffDNSClient, "alias-0.example", netip.MustParseAddr("203.0.113.10")))
			hAssertSniffDNSBounds(t, cache)
		})
		t.Run(fmt.Sprintf("addresses-%d", count), func(t *testing.T) {
			t.Parallel()
			cache, _ := hNewSniffDNSCache(4, time.Minute)
			var answer []mDNS.RR
			for index := 1; index <= count; index++ {
				answer = append(answer, hSniffDNSA("service.example.", fmt.Sprintf("203.0.113.%d", index), 60))
			}
			cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("service.example.", mDNS.TypeA, answer...))
			for index := 1; index <= count; index++ {
				require.Equal(t, count == 16, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", netip.MustParseAddr(fmt.Sprintf("203.0.113.%d", index))))
			}
			hAssertSniffDNSBounds(t, cache)
		})
	}
	cache, _ := hNewSniffDNSCache(4, time.Minute)
	var v4s, v6s []mDNS.RR
	for index := 1; index <= 16; index++ {
		v4s = append(v4s, hSniffDNSA("service.example.", fmt.Sprintf("203.0.113.%d", index), 60))
		v6s = append(v6s, hSniffDNSAAAA("service.example.", fmt.Sprintf("2001:db8::%x", index), 60))
	}
	cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("service.example.", mDNS.TypeA, v4s[:8]...))
	cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("service.example.", mDNS.TypeAAAA, v6s[:8]...))
	require.Len(t, cache.entries, 2, "address families have independent LRU keys")
	require.Len(t, cache.lru.Front().Value.(*sniffDNSAssociation).addresses, 8)
	require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", netip.MustParseAddr("203.0.113.1")))
	require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", netip.MustParseAddr("2001:db8::1")))
	cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("service.example.", mDNS.TypeA, v4s...))
	require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", netip.MustParseAddr("2001:db8::1")), "a full A RRset does not discard AAAA evidence")
	cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("service.example.", mDNS.TypeAAAA, v6s...))
	require.Len(t, cache.entries, 2)
	for element := cache.lru.Front(); element != nil; element = element.Next() {
		require.Len(t, element.Value.(*sniffDNSAssociation).addresses, 16)
	}
	hAssertSniffDNSBounds(t, cache)
}

func TestH_SniffDNSAssociationsDomainValidation(t *testing.T) {
	t.Parallel()
	maximum := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for _, domain := range []string{"a", "MiXeD.Example.", "xn--bcher-kva.example", maximum, maximum + "."} {
		normalized, valid := sniffDNSDomain(domain)
		require.True(t, valid, domain)
		require.Equal(t, strings.ToLower(strings.TrimSuffix(domain, ".")), normalized)
	}
	invalidNames := []string{
		"", ".", "..", ".example", "service..example", "service.example..", " service.example", "service.example ",
		"-service.example", "service-.example", "*.example", "_service.example", "service/example", "service:443",
		"service\\.example", "service\x00.example", "bücher.example", "K.example", strings.Repeat("a", 64) + ".example", maximum + "x",
	}
	for _, domain := range invalidNames {
		normalized, valid := sniffDNSDomain(domain)
		require.False(t, valid, domain)
		require.Empty(t, normalized)
		cache, _ := hNewSniffDNSCache(4, time.Minute)
		cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply(domain, mDNS.TypeA, hSniffDNSA(domain, "203.0.113.10", 60)))
		require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, domain, netip.MustParseAddr("203.0.113.10")))
		require.Empty(t, cache.entries)
	}
	cache, _ := hNewSniffDNSCache(4, time.Minute)
	cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("k.example.", mDNS.TypeA, hSniffDNSA("k.example.", "203.0.113.10", 60)))
	require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "K.example", netip.MustParseAddr("203.0.113.10")), "no Unicode folding into an authorized ASCII name")
}

func TestH_SniffDNSAssociationsRejectInvalidIdentities(t *testing.T) {
	t.Parallel()
	cache, _ := hNewSniffDNSCache(4, time.Minute)
	address := netip.MustParseAddr("203.0.113.10")
	response := hSniffDNSReply("service.example.", mDNS.TypeA, hSniffDNSA("service.example.", address.String(), 60))
	for _, client := range []netip.Addr{
		{}, netip.MustParseAddr("::"), netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("224.0.0.1"),
		netip.MustParseAddr("::ffff:192.0.2.10"), netip.MustParseAddr("fe80::1%tun-test"),
	} {
		cache.record(hSniffDNSInbound, client, response)
		require.False(t, cache.matches(hSniffDNSInbound, client, "service.example", address), client.String())
		require.Empty(t, cache.entries)
	}
	cache.record("", hSniffDNSClient, response)
	require.False(t, cache.matches("", hSniffDNSClient, "service.example", address))
	require.Empty(t, cache.entries)
	cache.record(hSniffDNSInbound, hSniffDNSClient, response)
	require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", address))
	for _, destination := range []netip.Addr{
		{}, netip.MustParseAddr("::"), netip.MustParseAddr("::ffff:203.0.113.10"), netip.MustParseAddr("ff02::1"), netip.MustParseAddr("fe80::1%tun-test"),
	} {
		require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", destination), destination.String())
	}
	v6Client := netip.MustParseAddr("2001:db8::100")
	cache.record(hSniffDNSInbound, v6Client, response)
	require.True(t, cache.matches(hSniffDNSInbound, v6Client, "service.example", address))
	hAssertSniffDNSBounds(t, cache)
}

func TestH_SniffDNSAssociationsDisabledAndDefaultClock(t *testing.T) {
	t.Parallel()
	for _, settings := range []struct {
		capacity int
		maxTTL   time.Duration
	}{{0, time.Minute}, {-1, time.Minute}, {8, 0}, {8, -time.Second}} {
		cache, _ := hNewSniffDNSCache(settings.capacity, settings.maxTTL)
		cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("service.example.", mDNS.TypeA, hSniffDNSA("service.example.", "203.0.113.10", 60)))
		require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", netip.MustParseAddr("203.0.113.10")))
		require.Empty(t, cache.entries)
		cache.clear()
		hAssertSniffDNSBounds(t, cache)
	}
	cache := newSniffDNSAssociations(1, time.Hour, nil)
	cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("service.example.", mDNS.TypeA, hSniffDNSA("service.example.", "203.0.113.10", 3600)))
	require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", netip.MustParseAddr("203.0.113.10")))
	hAssertSniffDNSBounds(t, cache)
}

func TestH_SniffDNSAssociationsDoNotRetainDNSMessages(t *testing.T) {
	t.Parallel()
	cache, _ := hNewSniffDNSCache(4, time.Minute)
	a := hSniffDNSA("service.example.", "203.0.113.10", 60)
	response := hSniffDNSReply("service.example.", mDNS.TypeA, a)
	cache.record(hSniffDNSInbound, hSniffDNSClient, response)
	a.A[3] = 20
	a.Hdr.Name, a.Hdr.Ttl = "other.example.", 0
	response.Question[0].Name = "other.example."
	response.Answer = nil
	require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", netip.MustParseAddr("203.0.113.10")))
	require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", netip.MustParseAddr("203.0.113.20")))
	require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "other.example", netip.MustParseAddr("203.0.113.10")))
	hAssertSniffDNSBounds(t, cache)
}

func hSniffDNSWireResponse(t *testing.T, response *mDNS.Msg) *mDNS.Msg {
	t.Helper()
	wire, err := response.Pack()
	require.NoError(t, err)
	var unpacked mDNS.Msg
	require.NoError(t, unpacked.Unpack(wire))
	return &unpacked
}

func TestH_SniffDNSAssociationsWireAnswers(t *testing.T) {
	t.Parallel()
	for _, queryType := range []uint16{mDNS.TypeA, mDNS.TypeAAAA} {
		t.Run(mDNS.TypeToString[queryType], func(t *testing.T) {
			t.Parallel()
			cache, _ := hNewSniffDNSCache(8, time.Minute)
			address := netip.MustParseAddr("203.0.113.10")
			var addressRecord mDNS.RR = hSniffDNSA("edge.example.", address.String(), 60)
			if queryType == mDNS.TypeAAAA {
				address = netip.MustParseAddr("2001:db8::10")
				addressRecord = hSniffDNSAAAA("edge.example.", address.String(), 60)
			}
			response := hSniffDNSReply("service.example.", queryType,
				addressRecord,
				hSniffDNSCNAME("cdn.example.", "edge.example.", 30),
				hSniffDNSCNAME("service.example.", "cdn.example.", 10))
			response.Compress = true
			response.Extra = []mDNS.RR{
				hSniffDNSCNAME("service.example.", "attacker.example.", 60),
				hSniffDNSA("attacker.example.", "203.0.113.20", 60),
			}
			cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSWireResponse(t, response))
			require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", address))
			require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "edge.example", address))
			require.False(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", netip.MustParseAddr("203.0.113.20")))
			hAssertSniffDNSBounds(t, cache)
		})
	}
}

func TestH_SniffDNSAssociationsTruncatedWireRevokesOnlyQuestionFamily(t *testing.T) {
	t.Parallel()
	for _, queryType := range []uint16{mDNS.TypeA, mDNS.TypeAAAA} {
		t.Run(mDNS.TypeToString[queryType], func(t *testing.T) {
			t.Parallel()
			cache, _ := hNewSniffDNSCache(8, time.Minute)
			v4 := netip.MustParseAddr("203.0.113.10")
			v6 := netip.MustParseAddr("2001:db8::10")
			cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("service.example.", mDNS.TypeA, hSniffDNSA("service.example.", v4.String(), 60)))
			cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("service.example.", mDNS.TypeAAAA, hSniffDNSAAAA("service.example.", v6.String(), 60)))
			var addressRecord mDNS.RR = hSniffDNSA("service.example.", v4.String(), 60)
			if queryType == mDNS.TypeAAAA {
				addressRecord = hSniffDNSAAAA("service.example.", v6.String(), 60)
			}
			response := hSniffDNSReply("service.example.", queryType, addressRecord,
				&mDNS.TXT{
					Hdr: mDNS.RR_Header{Name: "padding.example.", Rrtype: mDNS.TypeTXT, Class: mDNS.ClassINET, Ttl: 60},
					Txt: []string{strings.Repeat("x", 250), strings.Repeat("y", 250), strings.Repeat("z", 250)},
				})
			response.Truncate(mDNS.MinMsgSize)
			actualResponse := hSniffDNSWireResponse(t, response)
			require.True(t, actualResponse.Truncated)
			require.NotEmpty(t, actualResponse.Answer, "retained address RRs in a TC response still must not authorize")
			cache.record(hSniffDNSInbound, hSniffDNSClient, actualResponse)
			require.Equal(t, queryType != mDNS.TypeA, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", v4))
			require.Equal(t, queryType != mDNS.TypeAAAA, cache.matches(hSniffDNSInbound, hSniffDNSClient, "service.example", v6))
			hAssertSniffDNSBounds(t, cache)
		})
	}
}

func TestH_SniffDNSAssociationsConcurrentRecords(t *testing.T) {
	t.Parallel()
	cache, _ := hNewSniffDNSCache(16, time.Minute)
	var workers sync.WaitGroup
	for index := 1; index <= 16; index++ {
		workers.Go(func() {
			client := netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", index))
			address := netip.MustParseAddr(fmt.Sprintf("203.0.113.%d", index))
			for iteration := 0; iteration < 100; iteration++ {
				cache.record(hSniffDNSInbound, client, hSniffDNSReply("service.example.", mDNS.TypeA, hSniffDNSA("service.example.", address.String(), 60)))
				if !cache.matches(hSniffDNSInbound, client, "service.example", address) {
					t.Errorf("worker %d lost its own DNS association", index)
					return
				}
				if cache.matches(hSniffDNSInbound, client, "unqueried.example", address) {
					t.Errorf("worker %d authorized an unqueried name", index)
					return
				}
			}
		})
	}
	workers.Wait()
	require.Len(t, cache.entries, 16)
	hAssertSniffDNSBounds(t, cache)
}

func TestH_SniffDNSAssociationsConcurrentClearAndEviction(t *testing.T) {
	t.Parallel()
	cache, clock := hNewSniffDNSCache(4, time.Minute)
	var workers sync.WaitGroup
	for index := 0; index < 8; index++ {
		workers.Go(func() {
			for iteration := 0; iteration < 200; iteration++ {
				domain := fmt.Sprintf("host-%d-%d.example", index, iteration%8)
				address := netip.MustParseAddr("203.0.113.10")
				cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply(domain, mDNS.TypeA, hSniffDNSA(domain, address.String(), 1)))
				cache.matches(hSniffDNSInbound, hSniffDNSClient, domain, address)
				if iteration%7 == 0 {
					cache.clear()
				}
				clock.advance(time.Millisecond)
				if cache.matches("other-tun", hSniffDNSClient, domain, address) {
					t.Errorf("worker %d leaked authorization across inbounds", index)
					return
				}
			}
		})
	}
	workers.Wait()
	hAssertSniffDNSBounds(t, cache)
	cache.clear()
	require.Empty(t, cache.entries)
	require.Zero(t, cache.lru.Len())
	cache.record(hSniffDNSInbound, hSniffDNSClient, hSniffDNSReply("fresh.example.", mDNS.TypeA, hSniffDNSA("fresh.example.", "203.0.113.10", 60)))
	require.True(t, cache.matches(hSniffDNSInbound, hSniffDNSClient, "fresh.example", netip.MustParseAddr("203.0.113.10")))
	hAssertSniffDNSBounds(t, cache)
}
