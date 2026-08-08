package interrupt

import (
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing/common/x/list"
)

type Group struct {
	access      sync.Mutex
	generation  uint64
	connections list.List[*groupConnItem]
}

type groupConnItem struct {
	conn       io.Closer
	isExternal bool
}

func NewGroup() *Group {
	return &Group{}
}

// Generation returns the current interrupt generation.
// Every call to Interrupt invalidates connection setup started under an older generation.
func (g *Group) Generation() uint64 {
	g.access.Lock()
	defer g.access.Unlock()
	return g.generation
}

func (g *Group) NewConn(conn net.Conn, isExternal bool) net.Conn {
	g.access.Lock()
	defer g.access.Unlock()
	item := g.connections.PushBack(&groupConnItem{conn, isExternal})
	return &Conn{Conn: conn, group: g, element: item}
}

// NewConnAtGeneration registers conn only if no interrupt occurred after generation was captured.
func (g *Group) NewConnAtGeneration(conn net.Conn, isExternal bool, generation uint64) (net.Conn, bool) {
	g.access.Lock()
	defer g.access.Unlock()
	if generation != g.generation {
		return nil, false
	}
	item := g.connections.PushBack(&groupConnItem{conn, isExternal})
	return &Conn{Conn: conn, group: g, element: item}, true
}

func (g *Group) NewPacketConn(conn net.PacketConn, isExternal bool) net.PacketConn {
	g.access.Lock()
	defer g.access.Unlock()
	item := g.connections.PushBack(&groupConnItem{conn, isExternal})
	return &PacketConn{PacketConn: conn, group: g, element: item}
}

// NewPacketConnAtGeneration registers conn only if no interrupt occurred after generation was captured.
func (g *Group) NewPacketConnAtGeneration(conn net.PacketConn, isExternal bool, generation uint64) (net.PacketConn, bool) {
	g.access.Lock()
	defer g.access.Unlock()
	if generation != g.generation {
		return nil, false
	}
	item := g.connections.PushBack(&groupConnItem{conn, isExternal})
	return &PacketConn{PacketConn: conn, group: g, element: item}, true
}

func (g *Group) Interrupt(interruptExternalConnections bool) {
	g.access.Lock()
	defer g.access.Unlock()
	g.generation++
	var toDelete []*list.Element[*groupConnItem]
	for element := g.connections.Front(); element != nil; element = element.Next() {
		if !element.Value.isExternal || interruptExternalConnections {
			element.Value.conn.Close()
			toDelete = append(toDelete, element)
		}
	}
	for _, element := range toDelete {
		g.connections.Remove(element)
	}
}
