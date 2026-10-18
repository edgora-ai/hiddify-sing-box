package libbox

import (
	"io"
	"sync"
)

type NeighborEntry struct {
	Address    string
	MacAddress string
	Hostname   string
}

type NeighborEntryIterator interface {
	Next() *NeighborEntry
	HasNext() bool
}

type NeighborSubscription struct {
	done      chan struct{}
	reader    io.ReadCloser
	closeOnce sync.Once
}

func (s *NeighborSubscription) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
		if s.reader != nil {
			_ = s.reader.Close()
		}
	})
}
