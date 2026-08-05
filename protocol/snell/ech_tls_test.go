package snell

import (
	stdtls "crypto/tls"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

type testECHTLSConn struct {
	net.Conn
	state stdtls.ConnectionState
}

func (c *testECHTLSConn) ConnectionState() stdtls.ConnectionState {
	return c.state
}

func TestValidateECHTLSConnection(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	conn := &testECHTLSConn{Conn: clientConn, state: stdtls.ConnectionState{ECHAccepted: true}}
	require.NoError(t, validateECHTLSConnection(conn, nil))
	require.NoError(t, validateECHTLSConnection(conn, []string{"", "custom-protocol"}))
	conn.state.NegotiatedProtocol = "custom-protocol"
	require.NoError(t, validateECHTLSConnection(conn, []string{"snell-ech/1", "custom-protocol"}))
	require.ErrorContains(t, validateECHTLSConnection(conn, []string{"snell-ech/1"}), "unexpected negotiated ALPN")
	conn.state.ECHAccepted = false
	require.ErrorContains(t, validateECHTLSConnection(conn, nil), "ECH was not accepted")
}
