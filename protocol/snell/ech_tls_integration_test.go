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
	testSnellECHTLSRaw(t, "", false)
}

func testSnellECHTLSRaw(t *testing.T, alpn string, withUTLS bool) {
	const (
		psk        = "snell-ech-tls-test-password"
		serverName = "snell.example.org"
		publicName = "public.example.org"
	)
	ctx, cancel := context.WithCancel(context.Background())

	echConfig, echKey, err := boxTLS.ECHKeygenDefault(publicName)
	require.NoError(t, err)
	serverTLSOptions := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Insecure:   true,
		ECH: &option.InboundECHOptions{
			Enabled: true,
			Key:     []string{echKey},
		},
	}
	if alpn != "" {
		serverTLSOptions.ALPN = []string{alpn}
	}
	serverTLS, err := boxTLS.NewServer(ctx, logger.NOP(), serverTLSOptions)
	require.NoError(t, err)

	service, err := snellv5.NewService(snellv5.ServiceOptions{
		PSK:      []byte(psk),
		Identity: true,
		Handler:  echTLSEchoHandler{},
	})
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		cancel()
		listener.Close()
		serverTLS.Close()
	})
	serverStates := make(chan echTLSObservation, 2)
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
				if err = validateECHTLSConnection(tlsConn, serverTLSOptions.ALPN); err != nil {
					tlsConn.Close()
					serverErrors <- err
					return
				}
				exporter, exportErr := snellprotocol.ExportIdentityKeyingMaterial(tlsConn)
				if exportErr != nil {
					tlsConn.Close()
					serverErrors <- exportErr
					return
				}
				serverStates <- echTLSObservation{state: tlsConn.ConnectionState(), exporter: exporter}
				err = service.NewConnection(ctx, tlsConn, M.SocksaddrFromNet(rawConn.RemoteAddr()), nil)
				if err != nil {
					tlsConn.Close()
					serverErrors <- err
				}
			}(rawConn)
		}
	}()

	clientTLSOptions := option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Insecure:   true,
		ECH: &option.OutboundECHOptions{
			Enabled: true,
			Config:  []string{echConfig},
		},
	}
	if alpn != "" {
		clientTLSOptions.ALPN = []string{alpn}
	}
	if withUTLS {
		clientTLSOptions.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}
	}
	clientTLS, err := boxTLS.NewClient(ctx, logger.NOP(), serverName, clientTLSOptions)
	require.NoError(t, err)
	require.NoError(t, boxTLS.ConfigureSnellECHClient(clientTLS))
	serverAddr := M.SocksaddrFromNet(listener.Addr())
	clientStates := make(chan echTLSObservation, 2)
	rawTLSDialer := &recordingECHTLSDialer{
		Dialer:       &echTLSDialer{Dialer: boxTLS.NewDialer(N.SystemDialer, clientTLS), alpn: []string(clientTLSOptions.ALPN)},
		observations: clientStates,
	}

	client, err := snellv4.NewClient(snellv4.ClientOptions{
		PSK:      []byte(psk),
		Identity: snellprotocol.IdentityV2,
		Reuse:    true,
		Dialer:   rawTLSDialer,
		Server:   serverAddr,
	})
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	require.NoError(t, client.Preconnect(ctx, 1))
	assertSnellECHTLSState(t, clientStates, serverStates, serverErrors, alpn, false)

	for index, payload := range [][]byte{[]byte("first reused stream"), []byte("second reused stream")} {
		conn, err := client.DialContext(ctx, M.ParseSocksaddr("destination.example:443"))
		require.NoError(t, err)
		_ = index
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
	assertSnellECHTLSState(t, clientStates, serverStates, serverErrors, alpn, !withUTLS)
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

type echTLSObservation struct {
	state    boxTLS.ConnectionState
	exporter []byte
}

type recordingECHTLSDialer struct {
	N.Dialer
	observations chan<- echTLSObservation
}

func (d *recordingECHTLSDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	exporter, err := snellprotocol.ExportIdentityKeyingMaterial(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	d.observations <- echTLSObservation{state: conn.(echTLSConnection).ConnectionState(), exporter: exporter}
	return conn, nil
}

func assertSnellECHTLSState(t *testing.T, clientStates <-chan echTLSObservation, serverStates <-chan echTLSObservation, serverErrors <-chan error, alpn string, resumed bool) {
	t.Helper()
	var clientObservation echTLSObservation
	select {
	case clientObservation = <-clientStates:
	case err := <-serverErrors:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for client ECH-TLS handshake")
	}
	select {
	case serverObservation := <-serverStates:
		require.True(t, clientObservation.state.ECHAccepted)
		require.True(t, serverObservation.state.ECHAccepted)
		require.Equal(t, resumed, clientObservation.state.DidResume)
		require.Equal(t, resumed, serverObservation.state.DidResume)
		require.Equal(t, alpn, clientObservation.state.NegotiatedProtocol)
		require.Equal(t, alpn, serverObservation.state.NegotiatedProtocol)
		require.Equal(t, clientObservation.exporter, serverObservation.exporter)
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
