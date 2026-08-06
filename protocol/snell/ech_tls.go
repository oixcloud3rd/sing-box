package snell

import (
	"context"
	stdtls "crypto/tls"
	"net"

	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type echTLSConnection interface {
	ConnectionState() stdtls.ConnectionState
}

func validateECHTLSConnection(conn net.Conn, alpn []string) error {
	tlsConn, loaded := conn.(echTLSConnection)
	if !loaded {
		return E.New("snell: invalid ECH-TLS connection")
	}
	state := tlsConn.ConnectionState()
	if !state.ECHAccepted {
		return E.New("snell: ECH was not accepted")
	}
	if len(alpn) > 0 && !common.Contains(alpn, state.NegotiatedProtocol) {
		return E.New("snell: unexpected negotiated ALPN: ", state.NegotiatedProtocol)
	}
	return nil
}

type echTLSDialer struct {
	boxtls.Dialer
	alpn []string
}

func (d *echTLSDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	conn, err := d.DialTLSContext(ctx, destination)
	if err != nil {
		return nil, err
	}
	if err = validateECHTLSConnection(conn, d.alpn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
