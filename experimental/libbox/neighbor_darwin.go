//go:build darwin

package libbox

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"

	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"

	xroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func SubscribeNeighborTable(listener NeighborUpdateListener) (*NeighborSubscription, error) {
	entries, err := route.ReadNeighborEntries()
	if err != nil {
		return nil, E.Cause(err, "initial neighbor dump")
	}
	table := make(map[netip.Addr]net.HardwareAddr)
	for _, entry := range entries {
		table[entry.Address] = entry.MACAddress
	}
	routeSocket, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, E.Cause(err, "open route socket")
	}
	err = unix.SetNonblock(routeSocket, true)
	if err != nil {
		_ = unix.Close(routeSocket)
		return nil, E.Cause(err, "set route socket nonblock")
	}
	routeSocketFile := os.NewFile(uintptr(routeSocket), "route")
	if routeSocketFile == nil {
		_ = unix.Close(routeSocket)
		return nil, E.Cause(os.ErrInvalid, "wrap route socket")
	}
	subscription := &NeighborSubscription{
		done:   make(chan struct{}),
		reader: routeSocketFile,
	}
	subscription.start(listener, table)
	return subscription, nil
}

func (s *NeighborSubscription) start(listener NeighborUpdateListener, table map[netip.Addr]net.HardwareAddr) {
	// Own the reader before the synchronous callback, which may cancel the subscription.
	listener.UpdateNeighborTable(tableToIterator(table))
	select {
	case <-s.done:
		return
	default:
	}
	go s.loop(listener, table)
}

func (s *NeighborSubscription) loop(listener NeighborUpdateListener, table map[netip.Addr]net.HardwareAddr) {
	defer s.Close()
	buffer := buf.NewPacket()
	defer buffer.Release()
	for {
		select {
		case <-s.done:
			return
		default:
		}
		n, err := s.reader.Read(buffer.FreeBytes())
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			select {
			case <-s.done:
				return
			default:
			}
			continue
		}
		messages, err := xroute.ParseRIB(xroute.RIBTypeRoute, buffer.FreeBytes()[:n])
		if err != nil {
			continue
		}
		changed := false
		for _, message := range messages {
			routeMessage, isRouteMessage := message.(*xroute.RouteMessage)
			if !isRouteMessage {
				continue
			}
			if routeMessage.Flags&unix.RTF_LLINFO == 0 {
				continue
			}
			address, mac, isDelete, ok := route.ParseRouteNeighborMessage(routeMessage)
			if !ok {
				continue
			}
			if isDelete {
				if _, exists := table[address]; exists {
					delete(table, address)
					changed = true
				}
			} else {
				existing, exists := table[address]
				if !exists || !slices.Equal(existing, mac) {
					table[address] = mac
					changed = true
				}
			}
		}
		if changed {
			listener.UpdateNeighborTable(tableToIterator(table))
		}
	}
}

func ReadBootpdLeases() NeighborEntryIterator {
	leaseIPToMAC, ipToHostname, macToHostname := route.ReloadLeaseFiles([]string{"/var/db/dhcpd_leases"})
	entries := make([]*NeighborEntry, 0, len(leaseIPToMAC))
	for address, mac := range leaseIPToMAC {
		entry := &NeighborEntry{
			Address:    address.String(),
			MacAddress: mac.String(),
		}
		hostname, found := ipToHostname[address]
		if !found {
			hostname = macToHostname[mac.String()]
		}
		entry.Hostname = hostname
		entries = append(entries, entry)
	}
	return &neighborEntryIterator{entries}
}
