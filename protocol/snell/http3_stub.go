//go:build !with_quic

package snell

import (
	"context"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

func newHTTP3Dialer(ctx context.Context, logger log.ContextLogger, dialer N.Dialer, fallback N.Dialer, options option.SnellOutboundOptions) (transportDialer, error) {
	return nil, E.New("snell: HTTP/3 requires building with with_quic")
}
