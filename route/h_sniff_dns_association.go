package route

import (
	"container/list"
	"net/netip"
	"strings"
	"sync"
	"time"

	mDNS "github.com/miekg/dns"
)

const (
	sniffDNSMaxAliases   = 16
	sniffDNSMaxAddresses = 16
)

type sniffDNSAssociationKey struct {
	inbound   string
	client    netip.Addr
	domain    string
	queryType uint16
}

type sniffDNSAssociation struct {
	key       sniffDNSAssociationKey
	addresses map[netip.Addr]time.Time
}

// sniffDNSAssociations is a bounded, memory-only record of DNS answers delivered
// to a client. It deliberately has no IP-to-domain lookup or metadata dependency.
// A client is an inbound plus a source IP, not a UDP port or an application: two
// applications sharing that identity cannot be distinguished by this helper.
// Nothing is recorded until a caller explicitly uses record.
type sniffDNSAssociations struct {
	mu           sync.Mutex
	capacity     int
	maxTTL       time.Duration
	now          func() time.Time
	entries      map[sniffDNSAssociationKey]*list.Element
	lru          list.List
	generation   uint64
	pending      map[sniffDNSAssociationKey][]*sniffDNSDelivery
	pendingCount int
}

// Nonpositive capacity or maxTTL disables recording. A nil clock uses time.Now.
// Capacity counts inbound/client/domain/query-type keys, each with at most 16 addresses.
func newSniffDNSAssociations(capacity int, maxTTL time.Duration, now func() time.Time) *sniffDNSAssociations {
	if now == nil {
		now = time.Now
	}
	return &sniffDNSAssociations{
		capacity: capacity,
		maxTTL:   maxTTL,
		now:      now,
		entries:  make(map[sniffDNSAssociationKey]*list.Element),
		pending:  make(map[sniffDNSAssociationKey][]*sniffDNSDelivery),
	}
}

// record must only be called for a response successfully delivered to this
// inbound/client, not for a generic resolver cache hit or cached metadata.Domain.
// The caller owns request/response correlation and must not mutate response
// during this call. No response objects are retained.
//
// A response replaces or revokes only its queried address family, never extends
// the other family's TTL. NXDOMAIN conservatively revokes both families of this
// inbound/client/domain. Without exactly one valid A/AAAA question name there is
// no unambiguous association key to revoke.
func (s *sniffDNSAssociations) record(inbound string, client netip.Addr, response *mDNS.Msg) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recordLocked(inbound, client, response)
}

func (s *sniffDNSAssociations) recordLocked(inbound string, client netip.Addr, response *mDNS.Msg) {
	if inbound == "" || !sniffDNSValidAddress(client) || response == nil || len(response.Question) != 1 {
		return
	}
	question := response.Question[0]
	domain, valid := sniffDNSDomain(question.Name)
	if !valid || (question.Qtype != mDNS.TypeA && question.Qtype != mDNS.TypeAAAA) {
		return
	}
	key := sniffDNSAssociationKey{inbound: inbound, client: client, domain: domain, queryType: question.Qtype}

	s.removeLocked(s.entries[key])
	if response.Response && response.Opcode == mDNS.OpcodeQuery && question.Qclass == mDNS.ClassINET && response.Rcode == mDNS.RcodeNameError {
		otherKey := key
		if question.Qtype == mDNS.TypeA {
			otherKey.queryType = mDNS.TypeAAAA
		} else {
			otherKey.queryType = mDNS.TypeA
		}
		s.removeLocked(s.entries[otherKey])
	}
	if s.capacity <= 0 || s.maxTTL <= 0 || !response.Response || response.Opcode != mDNS.OpcodeQuery ||
		response.Truncated || response.Zero || response.Rcode != mDNS.RcodeSuccess || question.Qclass != mDNS.ClassINET {
		return
	}

	now := s.now()
	addresses := sniffDNSAnswerAddresses(response.Answer, domain, question.Qtype, s.maxTTL, now)
	if len(addresses) == 0 {
		return
	}
	entry := &sniffDNSAssociation{key: key, addresses: addresses}
	s.entries[key] = s.lru.PushFront(entry)
	for len(s.entries) > s.capacity {
		s.removeLocked(s.lru.Back())
	}
}

// matches only tests this exact forward association. It neither infers a domain
// from a shared IP nor authorizes another alias, inbound or client. Successful
// reads refresh LRU recency, not DNS lifetime. Mapped IPv6 identities are rejected
// rather than silently sharing authorization with their unmapped IPv4 form.
func (s *sniffDNSAssociations) matches(inbound string, client netip.Addr, domain string, address netip.Addr) bool {
	if inbound == "" || !sniffDNSValidAddress(client) || !sniffDNSValidAddress(address) {
		return false
	}
	domain, valid := sniffDNSDomain(domain)
	if !valid {
		return false
	}
	queryType := uint16(mDNS.TypeAAAA)
	if address.Is4() {
		queryType = mDNS.TypeA
	}
	key := sniffDNSAssociationKey{inbound: inbound, client: client, domain: domain, queryType: queryType}

	s.mu.Lock()
	defer s.mu.Unlock()

	element := s.entries[key]
	if element == nil {
		return false
	}
	entry := element.Value.(*sniffDNSAssociation)
	now := s.now()
	for candidate, expires := range entry.addresses {
		if !now.Before(expires) {
			delete(entry.addresses, candidate)
		}
	}
	if len(entry.addresses) == 0 {
		s.removeLocked(element)
		return false
	}
	_, matched := entry.addresses[address]
	if matched {
		s.lru.MoveToFront(element)
	}
	return matched
}

// clear drops all authorization. The owner must call it at lifecycle boundaries
// and prevent old in-flight DNS deliveries from recording into a new lifecycle.
func (s *sniffDNSAssociations) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = make(map[sniffDNSAssociationKey]*list.Element)
	s.lru.Init()
	s.generation++
	for _, pending := range s.pending {
		for _, delivery := range pending {
			delivery.finished = true
			close(delivery.done)
		}
	}
	s.pending = make(map[sniffDNSAssociationKey][]*sniffDNSDelivery)
	s.pendingCount = 0
}

func (s *sniffDNSAssociations) removeLocked(element *list.Element) {
	if element != nil {
		delete(s.entries, element.Value.(*sniffDNSAssociation).key)
		s.lru.Remove(element)
	}
}

type sniffDNSAlias struct {
	target string
	ttl    time.Duration
}

// Only Answer A/AAAA records at the end of an unambiguous CNAME chain can
// authorize the queried name. Authority and Additional are never inputs here.
// Limits count RRs, including duplicates and unrelated owners; oversized or
// malformed relevant records fail closed instead of truncating the evidence.
func sniffDNSAnswerAddresses(answer []mDNS.RR, domain string, queryType uint16, maxTTL time.Duration, now time.Time) map[netip.Addr]time.Time {
	aliases := make(map[string]sniffDNSAlias)
	addresses := make(map[string]map[netip.Addr]time.Duration)
	var aliasCount, addressCount int
	for _, record := range answer {
		var header *mDNS.RR_Header
		var address netip.Addr
		var target string
		var expectedType uint16
		switch record := record.(type) {
		case *mDNS.CNAME:
			if record == nil {
				return nil
			}
			header, expectedType = &record.Hdr, mDNS.TypeCNAME
			var valid bool
			target, valid = sniffDNSDomain(record.Target)
			if !valid {
				return nil
			}
		case *mDNS.A:
			if record == nil {
				return nil
			}
			header, expectedType = &record.Hdr, mDNS.TypeA
			// A's net.IP may use Go's 16-byte IPv4 representation. Only an
			// actual A RR is canonicalized this way, never an AAAA RR or key.
			var valid bool
			address, valid = netip.AddrFromSlice(record.A.To4())
			if !valid || !sniffDNSValidAddress(address) {
				return nil
			}
		case *mDNS.AAAA:
			if record == nil {
				return nil
			}
			header, expectedType = &record.Hdr, mDNS.TypeAAAA
			var valid bool
			address, valid = netip.AddrFromSlice(record.AAAA)
			if !valid || !address.Is6() || !sniffDNSValidAddress(address) {
				return nil
			}
		case nil:
			return nil
		default:
			// Other RR types, including DNSSEC signatures, confer no addresses.
			continue
		}
		owner, valid := sniffDNSDomain(header.Name)
		if !valid || header.Class != mDNS.ClassINET || header.Rrtype != expectedType {
			return nil
		}
		ttl := time.Duration(header.Ttl) * time.Second
		// RFC 2181 section 8: a TTL with its high bit set is treated as zero.
		if header.Ttl >= 1<<31 {
			ttl = 0
		}
		if expectedType == mDNS.TypeCNAME {
			aliasCount++
			if aliasCount > sniffDNSMaxAliases {
				return nil
			}
			if previous, exists := aliases[owner]; exists {
				if previous.target != target {
					return nil
				}
				ttl = min(ttl, previous.ttl)
			}
			aliases[owner] = sniffDNSAlias{target: target, ttl: ttl}
		} else {
			addressCount++
			if addressCount > sniffDNSMaxAddresses {
				return nil
			}
			if addresses[owner] == nil {
				addresses[owner] = make(map[netip.Addr]time.Duration)
			}
			if previous, exists := addresses[owner][address]; exists {
				ttl = min(ttl, previous)
			}
			addresses[owner][address] = ttl
		}
	}

	owner := domain
	chainTTL := maxTTL
	visited := make(map[string]struct{})
	for {
		if _, exists := visited[owner]; exists {
			return nil
		}
		visited[owner] = struct{}{}
		alias, exists := aliases[owner]
		if !exists {
			break
		}
		// A CNAME owner cannot also own an address RR, even of the other family.
		if len(addresses[owner]) != 0 {
			return nil
		}
		chainTTL = min(chainTTL, alias.ttl)
		owner = alias.target
	}

	result := make(map[netip.Addr]time.Time)
	for address, ttl := range addresses[owner] {
		if address.Is4() != (queryType == mDNS.TypeA) {
			continue
		}
		ttl = min(ttl, chainTTL)
		if ttl > 0 {
			result[address] = now.Add(ttl)
		}
	}
	return result
}

func sniffDNSValidAddress(address netip.Addr) bool {
	return address.IsValid() && !address.Is4In6() && address.Zone() == "" &&
		!address.IsUnspecified() && !address.IsMulticast()
}

// Accept only ASCII hostname labels (IDNs must already be punycode). Escaped DNS
// names, Unicode, wildcards and empty labels are not safe sniffed hostnames.
// Remove at most one final dot, and validate before lowercasing so Unicode case
// folding cannot turn a malformed DNS name into an authorized ASCII hostname.
func sniffDNSDomain(domain string) (string, bool) {
	domain = strings.TrimSuffix(domain, ".")
	if len(domain) == 0 || len(domain) > 253 {
		return "", false
	}
	start := 0
	for index := 0; index <= len(domain); index++ {
		if index == len(domain) || domain[index] == '.' {
			if index == start || index-start > 63 || domain[start] == '-' || domain[index-1] == '-' {
				return "", false
			}
			start = index + 1
			continue
		}
		character := domain[index]
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-') {
			return "", false
		}
	}
	return strings.ToLower(domain), true
}
