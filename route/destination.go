package route

import (
	"context"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func (m *ConnectionManager) selectDestination(
	ctx context.Context,
	strategy option.DestinationStrategy,
	metadata *adapter.InboundContext,
) (M.Socksaddr, []netip.Addr) {
	destination := metadata.Destination
	if metadata.RouteOverrideAddressSet {
		return destination, nil
	}
	if strategy.EffectiveStrategy() != C.DestinationStrategyPreferDestination {
		return destination, metadata.DestinationAddresses
	}
	if strategy.OverrideWithDomain == nil {
		return destination, nil
	}
	overrideOptions := strategy.OverrideWithDomain
	if overrideOptions.IPOnly && !destination.IsIP() {
		return destination, nil
	}
	if !isDomainOverrideProtocol(metadata.Protocol) || !M.IsDomainName(metadata.Domain) {
		return destination, nil
	}
	domain := normalizeOverrideDomain(metadata.Domain)
	if m.domainEvaluatorManager == nil {
		return destination, nil
	}
	evaluator, loaded := m.domainEvaluatorManager.Get(overrideOptions.Evaluator)
	if !loaded || !evaluator.Evaluate(ctx, metadata, domain) {
		return destination, nil
	}
	return M.Socksaddr{Fqdn: domain, Port: destination.Port}, nil
}

func isDomainOverrideProtocol(protocol string) bool {
	switch protocol {
	case C.ProtocolHTTP, C.ProtocolTLS, C.ProtocolQUIC:
		return true
	default:
		return false
	}
}

func normalizeOverrideDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}
