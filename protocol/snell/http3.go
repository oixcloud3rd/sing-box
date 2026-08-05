//go:build with_quic

package snell

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	congestion_meta1 "github.com/sagernet/sing-quic/congestion_meta1"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

type http3Session struct {
	conn   *quic.Conn
	client *http3.ClientConn
	udp    net.Conn
	refs   int
}

type http3Dialer struct {
	N.Dialer
	ctx        context.Context
	fallback   N.Dialer
	options    option.SnellTransportOptions
	server     M.Socksaddr
	host       string
	path       string
	tlsConfig  tls.Config
	bbrProfile congestion_meta2.Profile

	mu         sync.Mutex
	closed     bool
	generation context.Context
	cancel     context.CancelFunc
	retryAfter time.Time
	pending    chan struct{}
	current    *http3Session
	sessions   map[*http3Session]struct{}
}

func newHTTP3Dialer(ctx context.Context, logger log.ContextLogger, dialer N.Dialer, fallback N.Dialer, options option.SnellOutboundOptions) (transportDialer, error) {
	tlsOptions := *options.TLS
	tlsOptions.ALPN = []string{http3.NextProtoH3}
	tlsOptions.MinVersion = "1.3"
	tlsOptions.MaxVersion = "1.3"
	tlsOptions.UTLS = nil
	tlsOptions.Fragment = false
	tlsOptions.RecordFragment = false
	tlsOptions.Spoof = ""
	tlsOptions.SpoofMethod = ""
	tlsOptions.KernelTx = false
	tlsOptions.KernelRx = false
	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, tlsOptions)
	if err != nil {
		return nil, E.Cause(err, "create Snell HTTP/3 TLS client")
	}
	if err = tls.ConfigureSnellECHClient(tlsConfig); err != nil {
		return nil, err
	}
	profile := congestion_meta2.ProfileStandard
	if options.Transport.BBRProfile != nil {
		profile, err = congestion_meta2.ParseProfile(*options.Transport.BBRProfile)
		if err != nil {
			return nil, err
		}
	}
	generation, cancel := context.WithCancel(ctx)
	hash := sha256.Sum256([]byte(options.PSK))
	return &http3Dialer{
		Dialer: dialer, ctx: ctx, fallback: fallback,
		options: *options.Transport, server: options.ServerOptions.Build(),
		host: tlsConfig.ServerName(), path: fmt.Sprintf("/ws-tunnel-%x", hash[:12]),
		tlsConfig: tlsConfig, bbrProfile: profile,
		generation: generation, cancel: cancel, sessions: make(map[*http3Session]struct{}),
	}, nil
}

func (d *http3Dialer) DialContext(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, net.ErrClosed
	}
	generation := d.generation
	coolingDown := d.options.Fallback && time.Now().Before(d.retryAfter)
	d.mu.Unlock()

	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(generation, cancel)
	defer stop()
	defer cancel()
	if generation.Err() != nil {
		return nil, generation.Err()
	}
	if !coolingDown {
		timeout := 10 * time.Second
		if d.options.Fallback {
			timeout = 2 * time.Second
		}
		h3Ctx, h3Cancel := context.WithTimeout(ctx, timeout)
		conn, err := d.open(h3Ctx, generation)
		h3Cancel()
		if err == nil {
			return conn, nil
		}
		if !d.options.Fallback || ctx.Err() != nil {
			return nil, err
		}
		d.mu.Lock()
		if d.generation != generation || d.closed {
			d.mu.Unlock()
			return nil, net.ErrClosed
		}
		d.retryAfter = time.Now().Add(30 * time.Second)
		d.mu.Unlock()
	}
	conn, err := d.fallback.DialContext(ctx, N.NetworkTCP, d.server)
	if err != nil {
		return nil, err
	}
	err = ctx.Err()
	if err == nil {
		err = generation.Err()
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (d *http3Dialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("snell: HTTP/3 carries Snell packet connections over streams")
}

func (d *http3Dialer) get(ctx, generation context.Context) (*http3Session, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		d.mu.Lock()
		if d.closed || d.generation != generation {
			d.mu.Unlock()
			return nil, net.ErrClosed
		}
		if session := d.current; session != nil && session.conn.Context().Err() == nil {
			session.refs++
			d.mu.Unlock()
			return session, nil
		}
		if pending := d.pending; pending != nil {
			d.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-pending:
				continue
			}
		}
		pending := make(chan struct{})
		d.pending = pending
		d.mu.Unlock()

		session, err := d.connect(ctx)
		d.mu.Lock()
		if err == nil && (d.closed || d.generation != generation || ctx.Err() != nil) {
			session.conn.CloseWithError(0, "")
			session.udp.Close()
			err = net.ErrClosed
		}
		if err == nil {
			session.refs = 1
			d.current = session
			d.sessions[session] = struct{}{}
			context.AfterFunc(session.conn.Context(), func() {
				session.udp.Close()
				d.mu.Lock()
				delete(d.sessions, session)
				if d.current == session {
					d.current = nil
				}
				d.mu.Unlock()
			})
		}
		if d.pending == pending {
			d.pending = nil
		}
		close(pending)
		d.mu.Unlock()
		return session, err
	}
}

// QUIC needs a DNS-resolved ECH snapshot, rather than the TCP handshake hook.
type http3TLSConfig struct {
	tls.Config
	snapshot *tls.STDConfig
}

func (c *http3TLSConfig) STDConfig() (*tls.STDConfig, error) {
	return c.snapshot, nil
}

func (d *http3Dialer) connect(ctx context.Context) (*http3Session, error) {
	var config *tls.STDConfig
	var err error
	if resolver, loaded := d.tlsConfig.(interface {
		STDConfigContext(context.Context) (*tls.STDConfig, error)
	}); loaded {
		config, err = resolver.STDConfigContext(ctx)
	} else {
		config, err = d.tlsConfig.STDConfig()
		if err == nil {
			config = config.Clone()
		}
	}
	if err != nil {
		return nil, err
	}
	udp, err := d.Dialer.DialContext(ctx, N.NetworkUDP, d.server)
	if err != nil {
		return nil, err
	}
	conn, err := qtls.Dial(ctx, udp, &http3TLSConfig{Config: d.tlsConfig, snapshot: config}, snellHTTP3QUICConfig())
	if err != nil {
		udp.Close()
		return nil, err
	}
	state := conn.ConnectionState().TLS
	if !state.ECHAccepted || state.NegotiatedProtocol != http3.NextProtoH3 {
		conn.CloseWithError(0, "")
		udp.Close()
		return nil, E.New("snell: HTTP/3 requires accepted ECH and h3 ALPN")
	}
	switch d.options.QUICCongestionControl {
	case "", "reno":
		// Preserve quic-go's native New Reno controller.
	case "cubic":
		timeFunc := ntp.TimeFuncFromContext(d.ctx)
		if timeFunc == nil {
			timeFunc = time.Now
		}
		conn.SetCongestionControl(congestion_meta1.NewCubicSender(
			congestion_meta1.DefaultClock{TimeFunc: timeFunc}, conn.InitialPacketSize(), false))
	case "bbr":
		conn.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(conn.InitialPacketSize(), d.bbrProfile))
	}
	client := (&http3.Transport{DisableCompression: true, MaxResponseHeaderBytes: 8 * 1024}).NewClientConn(conn)
	return &http3Session{conn: conn, client: client, udp: udp}, nil
}

func snellHTTP3QUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: 10 * time.Second, MaxIdleTimeout: 30 * time.Second,
		KeepAlivePeriod: 10 * time.Second, MaxIncomingStreams: -1, MaxIncomingUniStreams: 3,
		InitialStreamReceiveWindow: 64 * 1024, MaxStreamReceiveWindow: 4 * 1024 * 1024,
		InitialConnectionReceiveWindow: 1024 * 1024, MaxConnectionReceiveWindow: 16 * 1024 * 1024,
		DisablePathMTUDiscovery: !C.IsLinux && !C.IsWindows,
	}
}

func (d *http3Dialer) open(ctx, generation context.Context) (_ net.Conn, err error) {
	session, err := d.get(ctx, generation)
	if err != nil {
		return nil, err
	}
	var stream *http3Conn
	defer func() {
		if err != nil {
			if stream != nil {
				stream.Close()
			} else {
				d.release(session)
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-session.conn.Context().Done():
		return nil, context.Cause(session.conn.Context())
	case <-session.client.ReceivedSettings():
	}
	if !session.client.Settings().EnableExtendedConnect {
		return nil, E.New("snell: server did not enable HTTP/3 Extended CONNECT")
	}
	request, err := session.client.OpenRequestStream(ctx)
	if err != nil {
		if ctx.Err() == nil {
			d.retire(session)
		}
		return nil, err
	}
	stream = &http3Conn{RequestStream: request, session: session, release: func() { d.release(session) }}
	cancelDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		stream.Close()
		close(cancelDone)
	})
	defer func() {
		if !stop() {
			<-cancelDone
		}
		if err == nil {
			err = ctx.Err()
		}
	}()
	if deadline, loaded := ctx.Deadline(); loaded {
		_ = stream.SetDeadline(deadline)
	}
	err = request.SendRequestHeader(&http.Request{
		Method: http.MethodConnect, Proto: "websocket", Host: d.host,
		URL: &url.URL{Scheme: "https", Host: d.host, Path: d.path},
	})
	if err != nil {
		return nil, err
	}
	response, err := request.ReadResponse()
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusServiceUnavailable {
			d.retire(session)
		}
		return nil, E.New("snell: HTTP/3 CONNECT status ", response.StatusCode)
	}
	_ = stream.SetDeadline(time.Time{})
	return stream, nil
}

func (d *http3Dialer) retire(session *http3Session) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.current == session {
		d.current = nil
	}
	if session.refs == 0 {
		session.conn.CloseWithError(0, "")
	}
}

func (d *http3Dialer) release(session *http3Session) {
	d.mu.Lock()
	defer d.mu.Unlock()
	session.refs--
	if session.refs == 0 && d.current != session {
		session.conn.CloseWithError(0, "")
	}
}

func (d *http3Dialer) resetLocked() {
	d.cancel()
	d.current = nil
	d.pending = nil
	d.retryAfter = time.Time{}
	for session := range d.sessions {
		session.conn.CloseWithError(0, "")
		session.udp.Close()
	}
	d.sessions = make(map[*http3Session]struct{})
}

func (d *http3Dialer) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.resetLocked()
		d.generation, d.cancel = context.WithCancel(d.ctx)
	}
}

func (d *http3Dialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		d.resetLocked()
	}
	return nil
}

type http3Conn struct {
	*http3.RequestStream
	session *http3Session
	release func()
	writeMu sync.Mutex
	closed  atomic.Bool
}

func (c *http3Conn) LocalAddr() net.Addr  { return c.session.conn.LocalAddr() }
func (c *http3Conn) RemoteAddr() net.Addr { return c.session.conn.RemoteAddr() }

func (c *http3Conn) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	state := c.session.conn.ConnectionState().TLS
	return state.ExportKeyingMaterial(label, context, length)
}

func (c *http3Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.RequestStream.Write(p)
}

func (c *http3Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.RequestStream.Close()
}

func (c *http3Conn) Close() error {
	if !c.closed.Swap(true) {
		// Cancel writes before waiting on any writer: flow control may block it.
		c.CancelRead(0)
		c.CancelWrite(0)
		c.release()
	}
	return nil
}
