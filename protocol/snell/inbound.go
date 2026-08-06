package snell

import (
	"context"
	"net"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.SnellInboundOptions](registry, C.TypeSnell, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type Inbound struct {
	inbound.Adapter
	router    adapter.ConnectionRouterEx
	logger    logger.ContextLogger
	listener  *listener.Listener
	tlsConfig tls.ServerConfig
	tlsALPN   []string
	service   snellprotocol.Service
	users     []option.SnellUser
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SnellInboundOptions) (adapter.Inbound, error) {
	echTLSEnabled, err := validateInboundOptions(options)
	if err != nil {
		return nil, err
	}
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeSnell, tag),
		router:  uot.NewRouter(router, logger),
		logger:  logger,
		users:   options.Users,
	}
	if echTLSEnabled {
		inbound.tlsConfig, err = tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, E.Cause(err, "create Snell ECH-TLS server")
		}
		inbound.tlsALPN = []string(options.TLS.ALPN)
	}
	var userList []int
	var keyList [][]byte
	if len(options.Users) > 0 {
		userList = make([]int, len(options.Users))
		keyList = make([][]byte, len(options.Users))
		for index, user := range options.Users {
			userList[index] = index
			keyList[index] = []byte(user.UserKey)
		}
	}
	switch options.Version {
	case 5:
		var obfsMode snellprotocol.ObfsMode
		obfsMode, err = snellprotocol.ParseObfsMode(options.ObfsOptions.ObfsMode)
		if err != nil {
			return nil, err
		}
		serviceOptions := snellv5.ServiceOptions{
			PSK:      []byte(options.PSK),
			Identity: options.Identity,
			ObfsMode: obfsMode,
			Handler:  inbound,
		}
		if len(options.Users) > 0 {
			var service *snellv5.MultiService[int]
			service, err = snellv5.NewMultiService[int](serviceOptions)
			if err != nil {
				return nil, err
			}
			err = service.UpdateUsers(userList, keyList)
			inbound.service = service
		} else {
			inbound.service, err = snellv5.NewService(serviceOptions)
		}
	case 6:
		var mode snellv6.Mode
		mode, err = snellv6.ParseMode(options.V6Options.Mode)
		if err != nil {
			return nil, err
		}
		serviceOptions := snellv6.ServerOptions{
			PSK:     []byte(options.PSK),
			Mode:    mode,
			Handler: inbound,
		}
		if len(options.Users) > 0 {
			var service *snellv6.MultiService[int]
			service, err = snellv6.NewMultiService[int](serviceOptions)
			if err != nil {
				return nil, err
			}
			err = service.UpdateUsers(userList, keyList)
			inbound.service = service
		} else {
			inbound.service, err = snellv6.NewService(serviceOptions)
		}
	case 0:
		return nil, E.New("snell: missing version")
	default:
		return nil, E.New("snell: unsupported version: ", options.Version)
	}
	if err != nil {
		return nil, err
	}
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	})
	return inbound, nil
}

func validateInboundOptions(options option.SnellInboundOptions) (bool, error) {
	if options.Identity && options.Version != 5 {
		return false, E.New("snell: inbound identity requires version 5")
	}
	hasTLS := options.TLS != nil
	if !hasTLS {
		return false, nil
	}
	if options.Version != 5 {
		return false, E.New("snell: ECH-TLS requires inbound version 5")
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

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		if err := h.tlsConfig.Start(); err != nil {
			return err
		}
	}
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	return common.Close(h.listener, h.tlsConfig)
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.tlsConfig != nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
			return
		}
		if err = validateECHTLSConnection(tlsConn, h.tlsALPN); err != nil {
			N.CloseOnHandshakeFailure(tlsConn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": ECH-TLS validation"))
			return
		}
		conn = tlsConn
	}
	err := h.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		if E.IsClosedOrCanceled(err) {
			h.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
		}
	}
}

func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_, metadata := adapter.ExtendContext(ctx)
	if source.IsValid() {
		metadata.Source = source
	}
	if destination.IsValid() {
		metadata.Destination = destination
	}
	h.newConnection(ctx, conn, *metadata, onClose)
}

func (h *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_, metadata := adapter.ExtendContext(ctx)
	if source.IsValid() {
		metadata.Source = source
	}
	if destination.IsValid() {
		metadata.Destination = destination
	}
	h.newPacketConnection(ctx, conn, *metadata, onClose)
}

func (h *Inbound) newConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	if len(h.users) > 0 {
		userIndex, loaded := auth.UserFromContext[int](ctx)
		if !loaded {
			N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
			return
		}
		user := h.users[userIndex].Name
		if user == "" {
			user = F.ToString(userIndex)
		} else {
			metadata.User = user
		}
		h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) newPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	if len(h.users) > 0 {
		userIndex, loaded := auth.UserFromContext[int](ctx)
		if !loaded {
			N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
			return
		}
		user := h.users[userIndex].Name
		if user == "" {
			user = F.ToString(userIndex)
		} else {
			metadata.User = user
		}
		h.logger.InfoContext(ctx, "[", user, "] inbound packet connection from ", metadata.Source)
	} else {
		h.logger.InfoContext(ctx, "inbound packet connection from ", metadata.Source)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}
