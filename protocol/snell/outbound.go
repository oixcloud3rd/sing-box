package snell

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.SnellOutboundOptions](registry, C.TypeSnell, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	ctx        context.Context
	logger     logger.ContextLogger
	dialer     N.Dialer
	client     snellClient
	serverAddr M.Socksaddr
	preconnect int

	lifecycleAccess  sync.Mutex
	started          bool
	closed           bool
	preconnectCancel context.CancelFunc
	preconnectDone   chan struct{}
}

var _ adapter.InterfaceUpdateListener = (*Outbound)(nil)

type snellClient interface {
	snellprotocol.Method
	DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	Reset()
	Close() error
}

type snellPreconnectClient interface {
	Preconnect(ctx context.Context, count int) error
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SnellOutboundOptions) (adapter.Outbound, error) {
	err := validateIdentityOptions(options)
	if err != nil {
		return nil, err
	}
	echTLSEnabled, err := validateECHTLSOptions(options)
	if err != nil {
		return nil, err
	}
	if err = validatePreconnectOptions(options, echTLSEnabled); err != nil {
		return nil, err
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	serverAddr := options.ServerOptions.Build()
	serverDialer := N.Dialer(outboundDialer)
	if echTLSEnabled {
		tlsConfig, err := tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, E.Cause(err, "create Snell ECH-TLS client")
		}
		if err = tls.ConfigureSnellECHClient(tlsConfig); err != nil {
			return nil, err
		}
		serverDialer = &echTLSDialer{Dialer: tls.NewDialer(outboundDialer, tlsConfig), alpn: []string(options.TLS.ALPN)}
	}
	var client snellClient
	switch options.Version {
	case 4:
		var obfsMode snellprotocol.ObfsMode
		obfsMode, err = snellprotocol.ParseObfsMode(options.ObfsOptions.ObfsMode)
		if err != nil {
			return nil, err
		}
		client, err = snellv4.NewClient(snellv4.ClientOptions{
			PSK:      []byte(options.PSK),
			UserKey:  []byte(options.UserKey),
			Identity: snellprotocol.IdentityVersion(common.PtrValueOrDefault(options.Identity)),
			Reuse:    options.Reuse,
			ObfsMode: obfsMode,
			ObfsHost: options.ObfsOptions.ObfsHost,
			Dialer:   serverDialer,
			Server:   serverAddr,
		})
	case 6:
		var mode snellv6.Mode
		mode, err = snellv6.ParseMode(options.V6Options.Mode)
		if err != nil {
			return nil, err
		}
		client, err = snellv6.NewClient(snellv6.ClientOptions{
			PSK:     []byte(options.PSK),
			UserKey: []byte(options.UserKey),
			Mode:    mode,
			Reuse:   options.Reuse,
			Dialer:  serverDialer,
			Server:  serverAddr,
		})
	case 0:
		return nil, E.New("snell: missing version")
	default:
		return nil, E.New("snell: unsupported version: ", options.Version)
	}
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeSnell, tag, options.Network.Build(), options.DialerOptions),
		ctx:        ctx,
		logger:     logger,
		dialer:     serverDialer,
		client:     client,
		serverAddr: serverAddr,
		preconnect: options.Preconnect,
	}
	return outbound, nil
}

func validateIdentityOptions(options option.SnellOutboundOptions) error {
	if options.Identity == nil {
		return nil
	}
	identity := *options.Identity
	if identity != 1 && identity != 2 {
		return E.New("snell: identity must be 1 or 2")
	}
	if options.Version != 4 {
		return E.New("snell: identity requires version 4")
	}
	if identity == 2 && (options.TLS == nil || !options.TLS.Enabled || options.TLS.ECH == nil || !options.TLS.ECH.Enabled) {
		return E.New("snell: identity v2 requires ECH-TLS")
	}
	return nil
}

func validatePreconnectOptions(options option.SnellOutboundOptions, echTLSEnabled bool) error {
	if options.Preconnect < 0 || options.Preconnect > 4 {
		return E.New("snell: preconnect must be between 0 and 4")
	}
	if options.Preconnect == 0 {
		return nil
	}
	if options.Version != 4 || !echTLSEnabled || !options.Reuse {
		return E.New("snell: preconnect requires version 4, ECH-TLS, and reuse")
	}
	return nil
}

func validateECHTLSOptions(options option.SnellOutboundOptions) (bool, error) {
	hasTLS := options.TLS != nil
	if !hasTLS {
		return false, nil
	}
	if options.Version != 4 {
		return false, E.New("snell: ECH-TLS requires version 4")
	}
	if !options.TLS.Enabled {
		return false, E.New("snell: ECH-TLS requires TLS")
	}
	if options.TLS.ECH == nil || !options.TLS.ECH.Enabled {
		return false, E.New("snell: ECH-TLS requires ECH")
	}
	obfsMode, err := snellprotocol.ParseObfsMode(options.ObfsOptions.ObfsMode)
	if err != nil {
		return false, err
	}
	if obfsMode != snellprotocol.ObfsModeNone {
		return false, E.New("snell: ECH-TLS cannot be combined with obfs")
	}
	return true, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	networkName := N.NetworkName(network)
	switch networkName {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.client.DialContext(ctx, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		conn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		if err != nil {
			return nil, err
		}
		packetConn, err := h.client.DialPacketConn(conn)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return bufio.NewBindPacketConn(packetConn, destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	conn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	if err != nil {
		return nil, err
	}
	packetConn, err := h.client.DialPacketConn(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return packetConn, nil
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	h.lifecycleAccess.Lock()
	defer h.lifecycleAccess.Unlock()
	h.stopPreconnectLocked()
	h.client.Reset()
	if h.started && !h.closed {
		h.startPreconnectLocked()
	}
}

func (h *Outbound) Close() error {
	h.lifecycleAccess.Lock()
	defer h.lifecycleAccess.Unlock()
	h.closed = true
	h.stopPreconnectLocked()
	return h.client.Close()
}

func (h *Outbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStarted {
		return nil
	}
	h.lifecycleAccess.Lock()
	defer h.lifecycleAccess.Unlock()
	if h.started || h.closed {
		return nil
	}
	h.started = true
	h.startPreconnectLocked()
	return nil
}

func (h *Outbound) startPreconnectLocked() {
	if h.preconnect == 0 {
		return
	}
	client, loaded := h.client.(snellPreconnectClient)
	if !loaded {
		return
	}
	ctx, cancel := context.WithCancel(h.ctx)
	done := make(chan struct{})
	h.preconnectCancel = cancel
	h.preconnectDone = done
	go func() {
		defer close(done)
		preconnectCtx, timeoutCancel := context.WithTimeout(ctx, 10*time.Second)
		defer timeoutCancel()
		if err := client.Preconnect(preconnectCtx, h.preconnect); err != nil && ctx.Err() == nil {
			h.logger.WarnContext(ctx, "Snell preconnect failed: ", err)
		}
	}()
}

func (h *Outbound) stopPreconnectLocked() {
	if h.preconnectCancel == nil {
		return
	}
	h.preconnectCancel()
	<-h.preconnectDone
	h.preconnectCancel = nil
	h.preconnectDone = nil
}
