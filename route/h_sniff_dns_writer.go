package route

import (
	"encoding/binary"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	dnsOutbound "github.com/sagernet/sing-box/protocol/dns"

	mDNS "github.com/miekg/dns"
)

// The connection retains only this factory, never an association table. Each
// parsed query captures the current generation before starting its exchange.
func (r *Router) sniffDNSObserver(metadata adapter.InboundContext) dnsOutbound.ResponseHandlerFactory {
	if metadata.InboundType != C.TypeTun || !sniffDNSValidAddress(metadata.Source.Addr) {
		return nil
	}
	return func() dnsOutbound.ResponseHandler {
		associations := r.sniffDNS.Load()
		if associations == nil {
			return nil
		}
		return func(wire []byte) ([]byte, func(error)) {
			var parsed mDNS.Msg
			if parsed.Unpack(wire) != nil {
				return nil, nil
			}
			ttlOffsets, valid := sniffDNSResponseTTLOffsets(wire, &parsed)
			if !valid {
				return nil, nil
			}
			seconds := max(associations.maxTTL/time.Second, 0)
			ttlCap := uint32(min(seconds, 1<<32-1))
			response := parsed.Copy()
			for _, section := range [][]mDNS.RR{response.Answer, response.Ns, response.Extra} {
				for _, record := range section {
					header := record.Header()
					if header.Rrtype != mDNS.TypeOPT {
						header.Ttl = sniffDNSDeliveryTTL(header.Ttl, ttlCap)
					}
				}
			}
			response.Compress = true
			replacement, err := response.Pack()
			if err != nil || len(replacement) > len(wire) || !sniffDNSOPTFlagsUnchanged(&parsed, response) {
				// Some incoming compression layouts cannot be reproduced as
				// compactly by Pack. Never grow an already-truncated UDP packet
				// or normalize OPT flags: changing only fixed-width TTL fields
				// preserves the original size, records and compression exactly.
				replacement = append([]byte(nil), wire...)
				for _, offset := range ttlOffsets {
					ttl := binary.BigEndian.Uint32(replacement[offset:])
					binary.BigEndian.PutUint32(replacement[offset:], sniffDNSDeliveryTTL(ttl, ttlCap))
				}
			}
			// Authorize only the actual wire to be written. The completion owns
			// the pending/write/record handshake, including negative responses.
			var delivered mDNS.Msg
			if delivered.Unpack(replacement) != nil {
				return nil, nil
			}
			return replacement, associations.beginDelivery(metadata.Inbound, metadata.Source.Addr, &delivered)
		}
	}
}

func sniffDNSDeliveryTTL(ttl uint32, cap uint32) uint32 {
	// RFC 2181: the high bit makes the effective TTL zero, not a long-lived
	// answer that may be turned into positive authorization by clamping it.
	if ttl >= 1<<31 {
		return 0
	}
	return min(ttl, cap)
}

func sniffDNSOPTFlagsUnchanged(original *mDNS.Msg, response *mDNS.Msg) bool {
	for index, section := range [][]mDNS.RR{original.Answer, original.Ns, original.Extra} {
		rewritten := [][]mDNS.RR{response.Answer, response.Ns, response.Extra}[index]
		for recordIndex, record := range section {
			if record.Header().Rrtype == mDNS.TypeOPT && record.Header().Ttl != rewritten[recordIndex].Header().Ttl {
				return false
			}
		}
	}
	return true
}

// Unpack tolerates certain incorrect counts and trailing bytes. Such wire must
// not confer authorization. Walking the original framing also gives the exact
// TTL positions for the length-preserving fallback, without touching OPT flags.
func sniffDNSResponseTTLOffsets(wire []byte, response *mDNS.Msg) ([]int, bool) {
	if len(wire) < 12 || int(binary.BigEndian.Uint16(wire[4:])) != len(response.Question) ||
		int(binary.BigEndian.Uint16(wire[6:])) != len(response.Answer) ||
		int(binary.BigEndian.Uint16(wire[8:])) != len(response.Ns) ||
		int(binary.BigEndian.Uint16(wire[10:])) != len(response.Extra) {
		return nil, false
	}
	offset := 12
	for range response.Question {
		_, next, err := mDNS.UnpackDomainName(wire, offset)
		if err != nil || next+4 > len(wire) {
			return nil, false
		}
		offset = next + 4
	}
	var ttlOffsets []int
	for _, section := range [][]mDNS.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range section {
			_, next, err := mDNS.UnpackDomainName(wire, offset)
			if err != nil || next+10 > len(wire) {
				return nil, false
			}
			if record.Header().Rrtype != mDNS.TypeOPT {
				ttlOffsets = append(ttlOffsets, next+4)
			}
			offset = next + 10 + int(binary.BigEndian.Uint16(wire[next+8:]))
			if offset > len(wire) {
				return nil, false
			}
		}
	}
	return ttlOffsets, offset == len(wire)
}
