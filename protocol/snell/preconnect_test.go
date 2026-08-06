package snell

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type lifecyclePreconnectClient struct {
	started chan int
	calls   atomic.Int32
	resets  atomic.Int32
	closed  atomic.Bool
}

func (c *lifecyclePreconnectClient) Preconnect(ctx context.Context, count int) error {
	c.calls.Add(1)
	c.started <- count
	<-ctx.Done()
	return ctx.Err()
}

func (c *lifecyclePreconnectClient) DialContext(context.Context, M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (c *lifecyclePreconnectClient) DialConn(net.Conn, M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (c *lifecyclePreconnectClient) DialEarlyConn(conn net.Conn, _ M.Socksaddr) net.Conn {
	return conn
}

func (c *lifecyclePreconnectClient) DialPacketConn(net.Conn) (N.NetPacketConn, error) {
	return nil, net.ErrClosed
}

func (c *lifecyclePreconnectClient) Reset() {
	c.resets.Add(1)
}

func (c *lifecyclePreconnectClient) Close() error {
	c.closed.Store(true)
	return nil
}

func TestPreconnectLifecycle(t *testing.T) {
	client := &lifecyclePreconnectClient{started: make(chan int, 2)}
	outbound := &Outbound{
		ctx:        context.Background(),
		logger:     logger.NOP(),
		client:     client,
		preconnect: 2,
	}
	if err := outbound.Start(adapter.StartStateStarted); err != nil {
		t.Fatal(err)
	}
	select {
	case count := <-client.started:
		if count != 2 {
			t.Fatalf("unexpected preconnect count: %d", count)
		}
	case <-time.After(time.Second):
		t.Fatal("startup preconnect did not start")
	}
	outbound.InterfaceUpdated()
	select {
	case count := <-client.started:
		if count != 2 {
			t.Fatalf("unexpected restarted preconnect count: %d", count)
		}
	case <-time.After(time.Second):
		t.Fatal("interface update did not restart preconnect")
	}
	if client.resets.Load() != 1 {
		t.Fatalf("unexpected reset count: %d", client.resets.Load())
	}
	if err := outbound.Close(); err != nil {
		t.Fatal(err)
	}
	if !client.closed.Load() {
		t.Fatal("client was not closed")
	}
}
