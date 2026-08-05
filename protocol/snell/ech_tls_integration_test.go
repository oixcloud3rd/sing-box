package snell

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestSnellECHTLSRaw(t *testing.T) {
	const (
		psk        = "snell-ech-tls-test-password"
		serverName = "snell.example.org"
		publicName = "public.example.org"
		alpn       = "h2"
	)
	ctx, cancel := context.WithCancel(context.Background())

	echConfig, echKey, err := boxTLS.ECHKeygenDefault(publicName)
	require.NoError(t, err)
	serverTLS, err := boxTLS.NewServer(ctx, logger.NOP(), option.InboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Insecure:   true,
		ALPN:       []string{alpn},
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
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		cancel()
		listener.Close()
		serverTLS.Close()
	})
	serverStates := make(chan boxTLS.ConnectionState, 2)
	serverErrors := make(chan error, 2)
	go func() {
		for {
			rawConn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
				default:
					serverErrors <- err
				}
				return
			}
			go func(rawConn net.Conn) {
				tlsConn, err := boxTLS.ServerHandshake(ctx, rawConn, serverTLS)
				if err != nil {
					rawConn.Close()
					serverErrors <- err
					return
				}
				serverStates <- tlsConn.ConnectionState()
				err = service.NewConnection(ctx, tlsConn, M.SocksaddrFromNet(rawConn.RemoteAddr()), nil)
				if err != nil {
					tlsConn.Close()
					serverErrors <- err
				}
			}(rawConn)
		}
	}()

	clientTLS, err := boxTLS.NewClient(ctx, logger.NOP(), serverName, option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Insecure:   true,
		ALPN:       []string{alpn},
		ECH: &option.OutboundECHOptions{
			Enabled: true,
			Config:  []string{echConfig},
		},
	})
	require.NoError(t, err)
	serverAddr := M.SocksaddrFromNet(listener.Addr())
	rawTLSDialer := boxTLS.NewDialer(N.SystemDialer, clientTLS)

	client, err := snellv4.NewClient(snellv4.ClientOptions{
		PSK:    []byte(psk),
		Reuse:  true,
		Dialer: rawTLSDialer,
		Server: serverAddr,
	})
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })

	for index, payload := range [][]byte{[]byte("first reused stream"), []byte("second reused stream")} {
		conn, err := client.DialContext(ctx, M.ParseSocksaddr("destination.example:443"))
		require.NoError(t, err)
		if index == 0 {
			assertSnellECHTLSState(t, serverStates, serverErrors, alpn)
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		_, err = conn.Write(payload)
		require.NoError(t, err)
		require.NoError(t, N.CloseWrite(conn))
		response, err := io.ReadAll(conn)
		require.NoError(t, err)
		require.Equal(t, payload, response)
		require.NoError(t, conn.Close())
	}

	rawPacketConn, err := rawTLSDialer.DialContext(ctx, N.NetworkTCP, serverAddr)
	require.NoError(t, err)
	packetConn, err := client.DialPacketConn(rawPacketConn)
	require.NoError(t, err)
	assertSnellECHTLSState(t, serverStates, serverErrors, alpn)
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

func assertSnellECHTLSState(t *testing.T, states <-chan boxTLS.ConnectionState, serverErrors <-chan error, alpn string) {
	t.Helper()
	select {
	case state := <-states:
		require.True(t, state.ECHAccepted)
		require.Equal(t, alpn, state.NegotiatedProtocol)
	case err := <-serverErrors:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for raw ECH-TLS handshake")
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

var _ snellprotocol.Handler = echTLSEchoHandler{}
