//go:build with_quic

package snell

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type http3TestStats struct {
	connections atomic.Int32
	requests    atomic.Int32
	tcp         atomic.Int32
}

func newHTTP3TestServer(t *testing.T, status int) (context.Context, option.SnellOutboundOptions, *http3TestStats) {
	t.Helper()
	const serverName = "snell.example.org"
	const psk = "snell-http3-test-password"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	echConfig, echKey, err := boxTLS.ECHKeygenDefault("public.example.org")
	require.NoError(t, err)
	key, cert, err := boxTLS.GenerateCertificate(nil, nil, time.Now, serverName, time.Now().Add(time.Hour))
	require.NoError(t, err)
	serverTLS, err := boxTLS.NewServer(ctx, logger.NOP(), option.InboundTLSOptions{
		Enabled: true, ServerName: serverName,
		ALPN:        []string{"h3", "snell-ech/1"},
		Certificate: []string{string(cert)}, Key: []string{string(key)},
		ECH: &option.InboundECHOptions{Enabled: true, Key: []string{echKey}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { serverTLS.Close() })
	tlsConfig, err := serverTLS.STDConfig()
	require.NoError(t, err)
	snellService, err := snellv5.NewService(snellv5.ServiceOptions{
		PSK: []byte(psk), Identity: true, Handler: echTLSEchoHandler{},
	})
	require.NoError(t, err)
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { tcp.Close() })
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { udp.Close() })
	stats := new(http3TestStats)
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				tlsConn, err := boxTLS.ServerHandshake(ctx, conn, serverTLS)
				if err != nil {
					conn.Close()
					return
				}
				if err = validateECHTLSConnection(tlsConn, []string{"snell-ech/1"}); err != nil {
					tlsConn.Close()
					return
				}
				stats.tcp.Add(1)
				if err = snellService.NewConnection(ctx, tlsConn, M.SocksaddrFromNet(conn.RemoteAddr()), nil); err != nil {
					tlsConn.Close()
				}
			}()
		}
	}()
	type connKey struct{}
	hash := sha256.Sum256([]byte(psk))
	server := &http3.Server{
		TLSConfig: tlsConfig,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			stats.connections.Add(1)
			return context.WithValue(ctx, connKey{}, conn)
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			stats.requests.Add(1)
			if r.Method != http.MethodConnect || r.Proto != "websocket" ||
				r.Host != serverName || r.URL.Path != fmt.Sprintf("/ws-tunnel-%x", hash[:12]) ||
				!r.TLS.ECHAccepted {
				http.Error(w, "invalid tunnel request", http.StatusBadRequest)
				return
			}
			w.WriteHeader(status)
			if status != http.StatusOK {
				return
			}
			conn := &http3TestConn{
				Stream: w.(http3.HTTPStreamer).HTTPStream(),
				conn:   r.Context().Value(connKey{}).(*quic.Conn),
			}
			if err := snellService.NewConnection(ctx, conn, M.SocksaddrFromNet(conn.RemoteAddr()), nil); err != nil {
				conn.Close()
			}
		}),
	}
	go func() { _ = server.Serve(udp) }()
	t.Cleanup(func() { server.Close() })
	address := M.SocksaddrFromNet(tcp.Addr())
	return ctx, option.SnellOutboundOptions{
		Version: 4,
		AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: address.Port},
			PSK:           psk, Identity: common.Ptr(2),
			Transport: &option.SnellTransportOptions{Type: "http3"},
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled: true, ServerName: serverName, Certificate: []string{string(cert)},
					ECH: &option.OutboundECHOptions{Enabled: true, Config: []string{echConfig}},
				},
			},
		},
	}, stats
}

type http3TestConn struct {
	*http3.Stream
	conn *quic.Conn
}

func (c *http3TestConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *http3TestConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }
func (c *http3TestConn) CloseWrite() error    { return c.Stream.Close() }
func (c *http3TestConn) Close() error {
	c.CancelRead(0)
	return c.Stream.Close()
}

func (c *http3TestConn) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	state := c.conn.ConnectionState().TLS
	return state.ExportKeyingMaterial(label, context, length)
}

func testHTTP3TCPEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	payload := []byte("snell over HTTP/3")
	_, err := conn.Write(payload)
	require.NoError(t, err)
	require.NoError(t, N.CloseWrite(conn))
	response, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Equal(t, payload, response)
}

func TestSnellHTTP3(t *testing.T) {
	ctx, options, stats := newHTTP3TestServer(t, http.StatusOK)
	options.Reuse = true
	out, err := NewOutbound(ctx, nil, logger.NOP(), "test", options)
	require.NoError(t, err)
	outbound := out.(*Outbound)
	t.Cleanup(func() { outbound.Close() })
	require.NoError(t, outbound.client.(snellPreconnectClient).Preconnect(ctx, 1))
	for range 2 {
		conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("destination.example:443"))
		require.NoError(t, err)
		testHTTP3TCPEcho(t, conn)
	}
	packet, err := out.ListenPacket(ctx, M.Socksaddr{})
	require.NoError(t, err)
	defer packet.Close()
	require.NoError(t, packet.SetDeadline(time.Now().Add(5*time.Second)))
	destination := M.ParseSocksaddr("203.0.113.1:443")
	_, err = packet.WriteTo([]byte("packet"), destination.UDPAddr())
	require.NoError(t, err)
	buffer := make([]byte, 128)
	n, address, err := packet.ReadFrom(buffer)
	require.NoError(t, err)
	require.Equal(t, "packet", string(buffer[:n]))
	require.Equal(t, destination, M.SocksaddrFromNet(address))
	require.EqualValues(t, 1, stats.connections.Load())
	require.EqualValues(t, 2, stats.requests.Load())
	require.Zero(t, stats.tcp.Load())

	outbound.InterfaceUpdated(ctx)
	conn, err := out.DialContext(ctx, N.NetworkTCP, destination)
	require.NoError(t, err)
	testHTTP3TCPEcho(t, conn)
	require.EqualValues(t, 2, stats.connections.Load())
}

func TestSnellHTTP3Fallback(t *testing.T) {
	ctx, options, stats := newHTTP3TestServer(t, http.StatusForbidden)
	for _, fallback := range []bool{false, true} {
		options.Transport.Fallback = fallback
		out, err := NewOutbound(ctx, nil, logger.NOP(), "test", options)
		require.NoError(t, err)
		t.Cleanup(func() { out.(*Outbound).Close() })
		conn, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("destination.example:443"))
		if !fallback {
			require.ErrorContains(t, err, "CONNECT status 403")
			require.Zero(t, stats.tcp.Load())
			continue
		}
		require.NoError(t, err)
		testHTTP3TCPEcho(t, conn)
		requests := stats.requests.Load()
		conn, err = out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("destination.example:443"))
		require.NoError(t, err)
		testHTTP3TCPEcho(t, conn)
		require.Equal(t, requests, stats.requests.Load(), "cooldown must bypass HTTP/3")
		require.EqualValues(t, 2, stats.tcp.Load())
	}
}

var _ snellprotocol.KeyingMaterialExporter = (*http3Conn)(nil)
