package snell

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2raywebsocket"
	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestSnellECHTLSTransport(t *testing.T) {
	const (
		psk        = "snell-ech-tls-test-password"
		serverName = "snell.example.org"
		publicName = "public.example.org"
	)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	echConfig, echKey, err := boxTLS.ECHKeygenDefault(publicName)
	require.NoError(t, err)
	serverTLS, err := boxTLS.NewServer(ctx, logger.NOP(), option.InboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Insecure:   true,
		ECH: &option.InboundECHOptions{
			Enabled: true,
			Key:     []string{echKey},
		},
	})
	require.NoError(t, err)

	service, err := snellv5.NewService(snellv5.ServiceOptions{
		PSK:     []byte(psk),
		Handler: echTLSEchoHandler{},
	})
	require.NoError(t, err)
	websocketServer, err := v2raywebsocket.NewServer(ctx, logger.NOP(), option.V2RayWebsocketOptions{
		Path: "/snell",
	}, serverTLS, &snellServiceHandler{service: service})
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		websocketServer.Close()
		listener.Close()
	})
	go func() {
		_ = websocketServer.Serve(listener)
	}()

	clientTLS, err := boxTLS.NewClient(ctx, logger.NOP(), serverName, option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Insecure:   true,
		ECH: &option.OutboundECHOptions{
			Enabled: true,
			Config:  []string{echConfig},
		},
	})
	require.NoError(t, err)
	serverAddr := M.SocksaddrFromNet(listener.Addr())
	websocketClient, err := v2raywebsocket.NewClient(ctx, N.SystemDialer, serverAddr, option.V2RayWebsocketOptions{
		Path: "/snell",
	}, clientTLS)
	require.NoError(t, err)
	t.Cleanup(func() { websocketClient.Close() })

	client, err := snellv4.NewClient(snellv4.ClientOptions{
		PSK:    []byte(psk),
		Reuse:  true,
		Dialer: &transportDialer{transport: websocketClient},
		Server: serverAddr,
	})
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })

	for _, payload := range [][]byte{[]byte("first reused stream"), []byte("second reused stream")} {
		conn, err := client.DialContext(ctx, M.ParseSocksaddr("destination.example:443"))
		require.NoError(t, err)
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		_, err = conn.Write(payload)
		require.NoError(t, err)
		require.NoError(t, N.CloseWrite(conn))
		response, err := io.ReadAll(conn)
		require.NoError(t, err)
		require.Equal(t, payload, response)
		require.NoError(t, conn.Close())
	}

	rawPacketConn, err := websocketClient.DialContext(ctx)
	require.NoError(t, err)
	packetConn, err := client.DialPacketConn(rawPacketConn)
	require.NoError(t, err)
	t.Cleanup(func() { packetConn.Close() })
	_ = rawPacketConn.SetDeadline(time.Now().Add(10 * time.Second))
	packetPayload := make([]byte, 1200)
	_, err = rand.Read(packetPayload)
	require.NoError(t, err)
	packetDestination := M.ParseSocksaddr("203.0.113.1:443")
	packetBuffer := buf.NewSize(512 + len(packetPayload))
	packetBuffer.Resize(512, 0)
	_, err = packetBuffer.Write(packetPayload)
	require.NoError(t, err)
	require.NoError(t, packetConn.WritePacket(packetBuffer, packetDestination))
	responseBuffer := buf.NewSize(2048)
	responseDestination, err := packetConn.ReadPacket(responseBuffer)
	require.NoError(t, err)
	require.Equal(t, packetDestination, responseDestination)
	require.True(t, bytes.Equal(packetPayload, responseBuffer.Bytes()))
	responseBuffer.Release()
}

type snellServiceHandler struct {
	service snellprotocol.Service
}

func (h *snellServiceHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if err := h.service.NewConnection(ctx, conn, source, onClose); err != nil {
		conn.Close()
	}
}

type echTLSEchoHandler struct{}

func (echTLSEchoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		payload, err := io.ReadAll(conn)
		if err == nil {
			_, err = conn.Write(payload)
		}
		closeWriteErr := N.CloseWrite(conn)
		if err == nil {
			err = closeWriteErr
		}
		closeErr := conn.Close()
		if err == nil {
			err = closeErr
		}
		if onClose != nil {
			onClose(err)
		}
	}()
}

func (echTLSEchoHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		var handlerErr error
		defer func() {
			closeErr := conn.Close()
			if handlerErr == nil {
				handlerErr = closeErr
			}
			if onClose != nil {
				onClose(handlerErr)
			}
		}()
		for {
			packet := buf.NewSize(64 * 1024)
			packet.Resize(512, 0)
			packetDestination, err := conn.ReadPacket(packet)
			if err != nil {
				packet.Release()
				handlerErr = err
				return
			}
			if err = conn.WritePacket(packet, packetDestination); err != nil {
				handlerErr = err
				return
			}
		}
	}()
}

var (
	_ adapter.V2RayServerTransportHandler = (*snellServiceHandler)(nil)
	_ snellprotocol.Handler               = echTLSEchoHandler{}
)
