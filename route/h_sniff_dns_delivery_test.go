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

// Separate prepare/complete calls deterministically model a successful wire
// write paused before its completion callback, without sleeps or network I/O.
func TestH_SniffDNSDeliveryNXDomainFencesLatePositives(t *testing.T) {
	for _, queryType := range []uint16{mDNS.TypeA, mDNS.TypeAAAA} {
		for _, negativeFirst := range []bool{false, true} {
			name := mDNS.TypeToString[queryType] + map[bool]string{false: "/positive-prepared-first", true: "/negative-prepared-first"}[negativeFirst]
			t.Run(name, func(t *testing.T) {
				cache, _ := hNewSniffDNSCache(16, time.Minute)
				v4, client, address4 := hPendingDNSFixture("fenced.test")
				address6 := netip.MustParseAddr("2001:db8::10")
				v6 := hSniffDNSReply("fenced.test.", mDNS.TypeAAAA, hSniffDNSAAAA("fenced.test.", address6.String(), 60))
				cache.beginDelivery("tun", client, v4)(nil)
				cache.beginDelivery("tun", client, v6)(nil)
				negative := hSniffDNSReply("FENCED.TEST.", queryType)
				negative.Rcode = mDNS.RcodeNameError
				var completeNegative func(error)
				if negativeFirst {
					completeNegative = cache.beginDelivery("tun", client, negative)
				}
				late4 := cache.beginDelivery("tun", client, v4)
				late6 := cache.beginDelivery("tun", client, v6)
				if !negativeFirst {
					completeNegative = cache.beginDelivery("tun", client, negative)
				}
				var unrelated []func(error)
				for _, scope := range []struct {
					inbound string
					client  netip.Addr
					domain  string
				}{
					{"other-tun", client, "fenced.test"},
					{"tun", netip.MustParseAddr("172.19.0.3"), "fenced.test"},
					{"tun", client, "other.test"},
				} {
					response := hSniffDNSReply(scope.domain+".", mDNS.TypeA, hSniffDNSA(scope.domain+".", address4.String(), 60))
					complete := cache.beginDelivery(scope.inbound, scope.client, response)
					unrelated = append(unrelated, func(err error) {
						complete(err)
						require.True(t, cache.matches(scope.inbound, scope.client, scope.domain, address4))
					})
				}
				require.True(t, cache.matches("tun", client, "fenced.test", address4), "preparing NXDOMAIN must not revoke")
				require.True(t, cache.matches("tun", client, "fenced.test", address6))
				completeNegative(nil)
				require.False(t, cache.matches("tun", client, "fenced.test", address4))
				require.False(t, cache.matches("tun", client, "fenced.test", address6))
				late4(nil)
				require.False(t, cache.matches("tun", client, "fenced.test", address4), "late positive revived a revoked address")

				// A new, non-overlapping delivery may recover, even while another
				// invalidated family is still waiting to run its old callback.
				fresh4 := netip.MustParseAddr("93.184.216.35")
				fresh6 := netip.MustParseAddr("2001:db8::20")
				cache.beginDelivery("tun", client, hSniffDNSReply("fenced.test.", mDNS.TypeA, hSniffDNSA("fenced.test.", fresh4.String(), 60)))(nil)
				cache.beginDelivery("tun", client, hSniffDNSReply("fenced.test.", mDNS.TypeAAAA, hSniffDNSAAAA("fenced.test.", fresh6.String(), 60)))(nil)
				late6(nil)
				late4(nil)
				late6(nil)
				completeNegative(nil)
				for _, address := range []netip.Addr{address4, address6} {
					require.False(t, cache.matches("tun", client, "fenced.test", address))
				}
				for _, address := range []netip.Addr{fresh4, fresh6} {
					require.True(t, cache.matches("tun", client, "fenced.test", address), "late/duplicate completion changed a fresh authorization")
				}
				for _, complete := range unrelated {
					complete(nil)
				}
				require.Zero(t, cache.pendingCount)
				require.Empty(t, cache.pending)
				hAssertSniffDNSBounds(t, cache)
			})
		}
	}
}

func TestH_SniffDNSDeliveryFailedWritesDoNotFenceOrRevoke(t *testing.T) {
	cache, _ := hNewSniffDNSCache(8, time.Minute)
	v4, client, address4 := hPendingDNSFixture("failed.test")
	address6 := netip.MustParseAddr("2001:db8::10")
	v6 := hSniffDNSReply("failed.test.", mDNS.TypeAAAA, hSniffDNSAAAA("failed.test.", address6.String(), 60))
	cache.beginDelivery("tun", client, v4)(nil)
	cache.beginDelivery("tun", client, v6)(nil)
	pendingAddress4 := netip.MustParseAddr("93.184.216.36")
	pendingAddress6 := netip.MustParseAddr("2001:db8::20")
	pending4 := cache.beginDelivery("tun", client, hSniffDNSReply("failed.test.", mDNS.TypeA, hSniffDNSA("failed.test.", pendingAddress4.String(), 60)))
	pending6 := cache.beginDelivery("tun", client, hSniffDNSReply("failed.test.", mDNS.TypeAAAA, hSniffDNSAAAA("failed.test.", pendingAddress6.String(), 60)))
	negative := hSniffDNSReply("failed.test.", mDNS.TypeA)
	negative.Rcode = mDNS.RcodeNameError
	failedNegative := cache.beginDelivery("tun", client, negative)
	failedAddress := netip.MustParseAddr("93.184.216.35")
	failedPositive := cache.beginDelivery("tun", client, hSniffDNSReply("failed.test.", mDNS.TypeA, hSniffDNSA("failed.test.", failedAddress.String(), 60)))
	for _, complete := range []func(error){failedNegative, failedPositive} {
		complete(errors.New("wire write failed"))
		complete(nil)
	}
	for _, address := range []netip.Addr{address4, address6} {
		require.True(t, cache.matches("tun", client, "failed.test", address), "failed write revoked an existing authorization")
	}
	require.False(t, cache.matches("tun", client, "failed.test", failedAddress))
	pending4(nil)
	pending6(nil)
	for _, address := range []netip.Addr{pendingAddress4, pendingAddress6} {
		require.True(t, cache.matches("tun", client, "failed.test", address), "failed write fenced a pending positive")
	}
	for _, address := range []netip.Addr{address4, address6} {
		require.False(t, cache.matches("tun", client, "failed.test", address))
	}
	require.Zero(t, cache.pendingCount)
	require.Empty(t, cache.pending)
}

func TestH_SniffDNSDeliveryRevocationFencesOnlyQueriedFamily(t *testing.T) {
	for _, rcode := range []int{mDNS.RcodeSuccess, mDNS.RcodeServerFailure} {
		for _, queryType := range []uint16{mDNS.TypeA, mDNS.TypeAAAA} {
			t.Run(mDNS.RcodeToString[rcode]+"/"+mDNS.TypeToString[queryType], func(t *testing.T) {
				cache, _ := hNewSniffDNSCache(8, time.Minute)
				v4, client, address4 := hPendingDNSFixture("family.test")
				address6 := netip.MustParseAddr("2001:db8::10")
				v6 := hSniffDNSReply("family.test.", mDNS.TypeAAAA, hSniffDNSAAAA("family.test.", address6.String(), 60))
				complete4 := cache.beginDelivery("tun", client, v4)
				complete6 := cache.beginDelivery("tun", client, v6)
				negative := hSniffDNSReply("family.test.", queryType)
				negative.Rcode = rcode
				cache.beginDelivery("tun", client, negative)(nil)
				complete4(nil)
				complete6(nil)
				require.Equal(t, queryType != mDNS.TypeA, cache.matches("tun", client, "family.test", address4))
				require.Equal(t, queryType != mDNS.TypeAAAA, cache.matches("tun", client, "family.test", address6))
				require.Zero(t, cache.pendingCount)
			})
		}
	}
}

func TestH_SniffDNSDeliveryConcurrentPositiveCompletionsFenceWithoutPrepareOrdering(t *testing.T) {
	for _, winnerFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "later-prepared-completes-first", true: "earlier-prepared-completes-first"}[winnerFirst], func(t *testing.T) {
			cache, clock := hNewSniffDNSCache(8, time.Minute)
			loser, client, loserAddress := hPendingDNSFixture("concurrent.test")
			winnerAddress := netip.MustParseAddr("93.184.216.35")
			winner := hSniffDNSReply("concurrent.test.", mDNS.TypeA, hSniffDNSA("concurrent.test.", winnerAddress.String(), 2))
			var completeWinner, completeLoser func(error)
			if winnerFirst {
				completeWinner = cache.beginDelivery("tun", client, winner)
				completeLoser = cache.beginDelivery("tun", client, loser)
			} else {
				completeLoser = cache.beginDelivery("tun", client, loser)
				completeWinner = cache.beginDelivery("tun", client, winner)
			}
			completeWinner(nil)
			require.True(t, cache.matches("tun", client, "concurrent.test", winnerAddress))
			require.False(t, cache.matches("tun", client, "concurrent.test", loserAddress))
			clock.advance(2 * time.Second)
			require.False(t, cache.matches("tun", client, "concurrent.test", winnerAddress))
			fresh := cache.beginDelivery("tun", client, winner)
			completeLoser(nil)
			require.False(t, cache.matches("tun", client, "concurrent.test", loserAddress), "late concurrent positive survived its fence after expiry")
			fresh(nil)
			completeLoser(nil)
			completeWinner(nil)
			require.True(t, cache.matches("tun", client, "concurrent.test", winnerAddress), "stale completion fenced a fresh delivery")
			clock.advance(2 * time.Second)
			require.False(t, cache.matches("tun", client, "concurrent.test", winnerAddress))
			require.Zero(t, cache.pendingCount)
			require.Empty(t, cache.pending)
			require.Empty(t, cache.entries)
		})
	}
}

func TestH_SniffDNSDeliveryOverflowPositivesNeverBypassFence(t *testing.T) {
	for _, test := range []struct {
		name      string
		capacity  int
		holders   int
		queryType uint16
	}{
		{"per-key", 8, 4, mDNS.TypeA},
		{"global-other-family", 1, 1, mDNS.TypeAAAA},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache, _ := hNewSniffDNSCache(test.capacity, time.Minute)
			holder, client, address := hPendingDNSFixture("overflow.test")
			var holders []func(error)
			for range test.holders {
				holders = append(holders, cache.beginDelivery("tun", client, holder))
			}
			response := holder
			freshAddress := netip.MustParseAddr("93.184.216.35")
			fresh := hSniffDNSReply("overflow.test.", mDNS.TypeA, hSniffDNSA("overflow.test.", freshAddress.String(), 60))
			if test.queryType == mDNS.TypeAAAA {
				address = netip.MustParseAddr("2001:db8::10")
				response = hSniffDNSReply("overflow.test.", mDNS.TypeAAAA, hSniffDNSAAAA("overflow.test.", address.String(), 60))
				freshAddress = netip.MustParseAddr("2001:db8::20")
				fresh = hSniffDNSReply("overflow.test.", mDNS.TypeAAAA, hSniffDNSAAAA("overflow.test.", freshAddress.String(), 60))
			}
			beforeNegative := cache.beginDelivery("tun", client, response)
			late := cache.beginDelivery("tun", client, response)
			lateAfterRecovery := cache.beginDelivery("tun", client, response)
			require.Equal(t, test.holders, cache.pendingCount)
			require.Len(t, cache.pending, 1)
			beforeNegative(nil)
			require.False(t, cache.matches("tun", client, "overflow.test", address), "untracked positive must decline authorization even before a revocation")
			require.Equal(t, test.holders, cache.pendingCount)
			negative := hSniffDNSReply("overflow.test.", mDNS.TypeA)
			negative.Rcode = mDNS.RcodeNameError
			completeNegative := cache.beginDelivery("tun", client, negative)
			completeNegative(nil)
			late(nil)
			require.False(t, cache.matches("tun", client, "overflow.test", address), "untracked positive bypassed NXDOMAIN")
			for _, complete := range holders {
				complete(nil)
			}
			require.Empty(t, cache.entries)
			require.Zero(t, cache.pendingCount)
			require.Empty(t, cache.pending)
			cache.beginDelivery("tun", client, fresh)(nil)
			lateAfterRecovery(nil)
			late(nil)
			completeNegative(nil)
			require.True(t, cache.matches("tun", client, "overflow.test", freshAddress))
			require.False(t, cache.matches("tun", client, "overflow.test", address))
			require.Zero(t, cache.pendingCount)
			require.Empty(t, cache.pending)
			hAssertSniffDNSBounds(t, cache)
		})
	}
}

func TestH_SniffDNSDeliveryClearFencesRegisteredOverflowAndNegativeCallbacks(t *testing.T) {
	cache, _ := hNewSniffDNSCache(1, time.Minute)
	response, client, address := hPendingDNSFixture("lifecycle.test")
	registered := cache.beginDelivery("tun", client, response)
	overflow := cache.beginDelivery("tun", client, response)
	negative := hSniffDNSReply("lifecycle.test.", mDNS.TypeAAAA)
	negative.Rcode = mDNS.RcodeNameError
	oldNegative := cache.beginDelivery("tun", client, negative)
	key := sniffDNSAssociationKey{inbound: "tun", client: client, domain: "lifecycle.test", queryType: mDNS.TypeA}
	done := cache.pending[key][0].done
	cache.clear()
	select {
	case <-done:
	default:
		t.Fatal("clear did not release the registered delivery waiter")
	}
	require.Zero(t, cache.pendingCount)
	require.Empty(t, cache.pending)
	require.Empty(t, cache.entries)
	freshAddress := netip.MustParseAddr("93.184.216.35")
	freshResponse := hSniffDNSReply("lifecycle.test.", mDNS.TypeA, hSniffDNSA("lifecycle.test.", freshAddress.String(), 60))
	fresh := cache.beginDelivery("tun", client, freshResponse)
	for _, complete := range []func(error){registered, overflow, oldNegative} {
		complete(nil)
		complete(nil)
	}
	require.Equal(t, 1, cache.pendingCount, "old completion removed new lifecycle's pending write")
	require.False(t, cache.matches("tun", client, "lifecycle.test", address))
	fresh(nil)
	oldNegative(nil)
	registered(nil)
	overflow(nil)
	require.True(t, cache.matches("tun", client, "lifecycle.test", freshAddress))
	require.False(t, cache.matches("tun", client, "lifecycle.test", address))
	require.Zero(t, cache.pendingCount)
	require.Empty(t, cache.pending)
}

func TestH_SniffDNSDeliveryLateCompletionDoesNotExtendTTL(t *testing.T) {
	for _, test := range []struct {
		name    string
		maxTTL  time.Duration
		answers []mDNS.RR
	}{
		{"address", time.Minute, []mDNS.RR{hSniffDNSA("ttl.test.", "93.184.216.34", 2)}},
		{"cap", 2 * time.Second, []mDNS.RR{hSniffDNSA("ttl.test.", "93.184.216.34", 60)}},
		{"CNAME", time.Minute, []mDNS.RR{
			hSniffDNSCNAME("ttl.test.", "target.test.", 2), hSniffDNSA("target.test.", "93.184.216.34", 60),
		}},
	} {
		for _, delay := range []time.Duration{time.Second, 2 * time.Second, 3 * time.Second} {
			t.Run(test.name+"/"+delay.String(), func(t *testing.T) {
				cache, clock := hNewSniffDNSCache(8, test.maxTTL)
				client := netip.MustParseAddr("172.19.0.2")
				address := netip.MustParseAddr("93.184.216.34")
				response := hSniffDNSReply("ttl.test.", mDNS.TypeA, test.answers...)
				expires := clock.now().Add(2 * time.Second)
				complete := cache.beginDelivery("tun", client, response)
				clock.advance(delay)
				complete(nil)
				key := sniffDNSAssociationKey{inbound: "tun", client: client, domain: "ttl.test", queryType: mDNS.TypeA}
				require.Contains(t, cache.entries, key)
				stored := cache.entries[key].Value.(*sniffDNSAssociation)
				require.Equal(t, expires, stored.addresses[address], "completion restarted the DNS lifetime")
				require.Equal(t, delay < 2*time.Second, cache.matches("tun", client, "ttl.test", address))
				if delay < 2*time.Second {
					clock.advance(2*time.Second - delay)
				}
				require.False(t, cache.matches("tun", client, "ttl.test", address), "exact expiry must not authorize")
				complete(nil)
				require.False(t, cache.matches("tun", client, "ttl.test", address), "duplicate completion renewed an expired answer")
				require.Empty(t, cache.entries)
				require.Zero(t, cache.pendingCount)
				require.Empty(t, cache.pending)
			})
		}
	}
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
