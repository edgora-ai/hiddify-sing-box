package route

import (
	"context"
	"net/netip"
	"time"

	mDNS "github.com/miekg/dns"
)

const sniffDNSDeliveryWait = 200 * time.Millisecond

type sniffDNSDelivery struct {
	key         sniffDNSAssociationKey
	addresses   map[netip.Addr]time.Time
	done        chan struct{}
	registered  bool
	invalidated bool
	finished    bool
}

// beginDelivery publishes only a pending write, never an authorization. The
// completion commits an answer only after its actual wire write succeeds. Only
// registered, unfenced positives may authorize: at either pending limit, decline
// authorization rather than let an untracked callback bypass revocation.
func (s *sniffDNSAssociations) beginDelivery(inbound string, client netip.Addr, response *mDNS.Msg) func(error) {
	if response == nil {
		return nil
	}
	response = response.Copy()
	s.mu.Lock()
	generation := s.generation
	// Start TTLs before the write; a delayed completion must not renew them.
	preparedAt := s.now()
	delivery := &sniffDNSDelivery{done: make(chan struct{})}
	if inbound != "" && sniffDNSValidAddress(client) && len(response.Question) == 1 &&
		response.Response && response.Opcode == mDNS.OpcodeQuery && !response.Truncated && !response.Zero &&
		response.Rcode == mDNS.RcodeSuccess && s.capacity > 0 && s.maxTTL > 0 {
		question := response.Question[0]
		domain, valid := sniffDNSDomain(question.Name)
		if valid && question.Qclass == mDNS.ClassINET && (question.Qtype == mDNS.TypeA || question.Qtype == mDNS.TypeAAAA) {
			delivery.key = sniffDNSAssociationKey{inbound: inbound, client: client, domain: domain, queryType: question.Qtype}
			delivery.addresses = sniffDNSAnswerAddresses(response.Answer, domain, question.Qtype, s.maxTTL, preparedAt)
			if len(delivery.addresses) > 0 && s.pendingCount < s.capacity && len(s.pending[delivery.key]) < 4 {
				s.pending[delivery.key] = append(s.pending[delivery.key], delivery)
				s.pendingCount++
				delivery.registered = true
			}
		}
	}
	s.mu.Unlock()
	return func(writeErr error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if delivery.finished {
			return
		}
		delivery.finished = true
		if writeErr == nil && generation == s.generation && !delivery.invalidated &&
			(len(delivery.addresses) == 0 || delivery.registered) {
			s.recordLocked(inbound, client, response, preparedAt)
		}
		if delivery.registered {
			pending := s.pending[delivery.key]
			for index, item := range pending {
				if item == delivery {
					pending = append(pending[:index], pending[index+1:]...)
					s.pendingCount--
					break
				}
			}
			if len(pending) == 0 {
				delete(s.pending, delivery.key)
			} else {
				s.pending[delivery.key] = pending
			}
		}
		close(delivery.done)
	}
}

// A client may receive a DNS datagram before its writer goroutine resumes. Wait
// only for already pending, exact domain/client/address deliveries, with a short
// deadline and request cancellation; never issue DNS or wait for unrelated work.
func (s *sniffDNSAssociations) matchesAfterDelivery(ctx context.Context, inbound string, client netip.Addr, domain string, address netip.Addr) bool {
	if ctx.Err() != nil {
		return false
	}
	if s.matches(inbound, client, domain, address) {
		return true
	}
	domain, valid := sniffDNSDomain(domain)
	if !valid || !sniffDNSValidAddress(client) || !sniffDNSValidAddress(address) {
		return false
	}
	queryType := uint16(mDNS.TypeAAAA)
	if address.Is4() {
		queryType = mDNS.TypeA
	}
	key := sniffDNSAssociationKey{inbound: inbound, client: client, domain: domain, queryType: queryType}
	var waiting []<-chan struct{}
	s.mu.Lock()
	for _, pending := range s.pending[key] {
		if _, exists := pending.addresses[address]; exists {
			waiting = append(waiting, pending.done)
		}
	}
	s.mu.Unlock()
	if len(waiting) == 0 {
		return s.matches(inbound, client, domain, address)
	}
	timer := time.NewTimer(sniffDNSDeliveryWait)
	defer timer.Stop()
	for _, done := range waiting {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return s.matches(inbound, client, domain, address)
		case <-done:
			if s.matches(inbound, client, domain, address) {
				return true
			}
		}
	}
	return s.matches(inbound, client, domain, address)
}
