package route

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func hPendingDNSFixture(name string) (*mDNS.Msg, netip.Addr, netip.Addr) {
	query := new(mDNS.Msg).SetQuestion(name+".", mDNS.TypeA)
	response := new(mDNS.Msg).SetReply(query)
	address := netip.MustParseAddr("93.184.216.34")
	response.Answer = []mDNS.RR{&mDNS.A{
		Hdr: mDNS.RR_Header{Name: name + ".", Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 60},
		A:   net.IP(address.AsSlice()),
	}}
	return response, netip.MustParseAddr("172.19.0.2"), address
}

type hPendingWaitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *hPendingWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func hWaitPendingResult(t *testing.T, result <-chan bool) bool {
	t.Helper()
	select {
	case matched := <-result:
		return matched
	case <-time.After(2 * time.Second):
		t.Fatal("pending DNS delivery did not finish within its bound")
		return false
	}
}

func TestH_SniffDNSDeliveryWaitsForActualSuccessfulWrite(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "successful-write", true: "failed-write"}[fail], func(t *testing.T) {
			cache := newSniffDNSAssociations(8, time.Minute, time.Now)
			response, client, address := hPendingDNSFixture("delivery.test")
			complete := cache.beginDelivery("tun", client, response)
			require.NotNil(t, complete)
			ctx := &hPendingWaitContext{Context: context.Background(), waiting: make(chan struct{})}
			result := make(chan bool, 1)
			go func() { result <- cache.matchesAfterDelivery(ctx, "tun", client, "delivery.test", address) }()
			select {
			case <-ctx.waiting:
			case <-time.After(time.Second):
				t.Fatal("connection did not wait for the already pending DNS write")
			}
			require.False(t, cache.matches("tun", client, "delivery.test", address))
			var writeErr error
			if fail {
				writeErr = errors.New("fixture write failed")
			}
			complete(writeErr)
			require.Equal(t, !fail, hWaitPendingResult(t, result))
			complete(nil)
			require.Equal(t, !fail, cache.matches("tun", client, "delivery.test", address))
			require.Zero(t, cache.pendingCount)
		})
	}
}

func TestH_SniffDNSDeliveryCancellationAndClear(t *testing.T) {
	for _, clearCache := range []bool{false, true} {
		t.Run(map[bool]string{false: "request-cancel", true: "generation-clear"}[clearCache], func(t *testing.T) {
			cache := newSniffDNSAssociations(8, time.Minute, time.Now)
			response, client, address := hPendingDNSFixture("cancel.test")
			complete := cache.beginDelivery("tun", client, response)
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &hPendingWaitContext{Context: base, waiting: make(chan struct{})}
			result := make(chan bool, 1)
			go func() { result <- cache.matchesAfterDelivery(ctx, "tun", client, "cancel.test", address) }()
			select {
			case <-ctx.waiting:
			case <-time.After(time.Second):
				t.Fatal("pending wait did not begin")
			}
			if clearCache {
				cache.clear()
			} else {
				cancel()
			}
			require.False(t, hWaitPendingResult(t, result))
			complete(errors.New("cancelled writer"))
			require.False(t, cache.matches("tun", client, "cancel.test", address))
			require.Zero(t, cache.pendingCount)
		})
	}
	cache := newSniffDNSAssociations(8, time.Minute, time.Now)
	response, client, address := hPendingDNSFixture("old-generation.test")
	complete := cache.beginDelivery("tun", client, response)
	cache.clear()
	complete(nil)
	require.False(t, cache.matches("tun", client, "old-generation.test", address))
}

func TestH_SniffDNSDeliveryDoesNotWaitForUnrelatedAnswers(t *testing.T) {
	cache := newSniffDNSAssociations(8, time.Minute, time.Now)
	response, client, address := hPendingDNSFixture("exact.test")
	complete := cache.beginDelivery("tun", client, response)
	defer complete(errors.New("fixture complete"))
	for _, test := range []struct {
		inbound string
		client  netip.Addr
		domain  string
		address netip.Addr
	}{
		{"other", client, "exact.test", address},
		{"tun", netip.MustParseAddr("172.19.0.3"), "exact.test", address},
		{"tun", client, "other.test", address},
		{"tun", client, "exact.test", netip.MustParseAddr("93.184.216.35")},
	} {
		ctx := &hPendingWaitContext{Context: context.Background(), waiting: make(chan struct{})}
		require.False(t, cache.matchesAfterDelivery(ctx, test.inbound, test.client, test.domain, test.address))
		select {
		case <-ctx.waiting:
			t.Fatal("unrelated pending answer caused a wait")
		default:
		}
	}
}

func TestH_SniffDNSDeliveryBoundAndCopiedResponse(t *testing.T) {
	cache := newSniffDNSAssociations(8, time.Minute, time.Now)
	response, client, address := hPendingDNSFixture("bounded.test")
	complete := cache.beginDelivery("tun", client, response)
	result := make(chan bool, 1)
	go func() {
		result <- cache.matchesAfterDelivery(context.Background(), "tun", client, "bounded.test", address)
	}()
	require.False(t, hWaitPendingResult(t, result))
	response.Answer[0].Header().Ttl = 0
	response.Question[0].Name = "mutated.test."
	complete(nil)
	require.True(t, cache.matches("tun", client, "bounded.test", address))
	require.False(t, cache.matches("tun", client, "mutated.test", address))
	require.Nil(t, cache.beginDelivery("tun", client, nil))
}

func TestH_SniffDNSDeliveryPendingLimits(t *testing.T) {
	for _, capacity := range []int{2, 8} {
		cache := newSniffDNSAssociations(capacity, time.Minute, time.Now)
		response, client, _ := hPendingDNSFixture("limit.test")
		var completions []func(error)
		for i := 0; i < 20; i++ {
			completions = append(completions, cache.beginDelivery("tun", client, response))
		}
		require.Equal(t, min(capacity, 4), cache.pendingCount)
		for _, complete := range completions {
			complete(errors.New("fixture releases outstanding write"))
		}
		require.Zero(t, cache.pendingCount)
		require.Empty(t, cache.pending)
	}
}
