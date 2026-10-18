package route

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	R "github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (r *Router) resetSniffDNSAssociations(rules []adapter.Rule) {
	for _, rule := range rules {
		if action, ok := rule.Action().(*R.RuleActionSniff); ok && action.PreserveDomainForFallbackProxy {
			// A new table also invalidates responses still in flight before a rule reload.
			r.sniffDNS.Store(newSniffDNSAssociations(1024, 5*time.Minute, time.Now))
			return
		}
	}
	r.sniffDNS.Store(nil)
}

func (r *Router) preserveFallbackProxyDomain(ctx context.Context, metadata *adapter.InboundContext, selectedRule adapter.Rule, chain []adapter.Outbound) {
	if selectedRule != nil || metadata.InboundType != C.TypeTun || metadata.Network != N.NetworkTCP ||
		metadata.PreMatch || metadata.FakeIP || metadata.SniffError != nil ||
		metadata.SniffedDomainForFallbackProxy == "" || !metadata.Destination.IsIP() ||
		metadata.Destination != metadata.SniffedDestination || metadata.RouteOriginalDestination.IsValid() ||
		len(metadata.DestinationAddresses) != 0 || len(chain) == 0 {
		return
	}
	if metadata.Protocol != C.ProtocolTLS && metadata.Protocol != C.ProtocolHTTP {
		return
	}
	leaf := chain[len(chain)-1]
	if leaf.Type() != C.TypeVMess {
		return
	}
	if _, isGroup := leaf.(adapter.OutboundGroup); isGroup {
		return
	}
	address := metadata.Destination.Addr.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() ||
		netip.MustParsePrefix("198.18.0.0/15").Contains(address) || netip.MustParsePrefix("100.64.0.0/10").Contains(address) {
		return
	}
	associations := r.sniffDNS.Load()
	if associations == nil || !associations.matchesAfterDelivery(ctx, metadata.Inbound, metadata.Source.Addr, metadata.SniffedDomainForFallbackProxy, address) || r.sniffDNS.Load() != associations {
		return
	}
	metadata.RouteOriginalDestination = metadata.Destination
	metadata.Destination = M.Socksaddr{Fqdn: metadata.SniffedDomainForFallbackProxy, Port: metadata.Destination.Port}
	metadata.DestinationAddresses = nil
}
