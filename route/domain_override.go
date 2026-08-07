package route

import (
	"context"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"

	"golang.org/x/sync/singleflight"
)

const (
	domainOverrideCacheCapacity = 2048
	domainOverrideNegativeTTL   = 10 * time.Second
)

type domainOverrideEvaluator struct {
	positive *freelru.Cache[string, struct{}]
	negative *freelru.Cache[string, struct{}]
	group    singleflight.Group
}

func newDomainOverrideEvaluator() *domainOverrideEvaluator {
	positive := common.Must1(freelru.New[string, struct{}](domainOverrideCacheCapacity, maphash.NewHasher[string]().Hash32, true))
	negative := common.Must1(freelru.New[string, struct{}](domainOverrideCacheCapacity, maphash.NewHasher[string]().Hash32, true))
	negative.SetLifetime(domainOverrideNegativeTTL)
	return &domainOverrideEvaluator{
		positive: positive,
		negative: negative,
	}
}

func isOverrideAddressWithDomainProtocol(protocol string) bool {
	switch protocol {
	case C.ProtocolHTTP, C.ProtocolTLS, C.ProtocolQUIC:
		return true
	default:
		return false
	}
}

func normalizeOverrideAddressDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}

func overrideAddressWithDomain(metadata *adapter.InboundContext) {
	metadata.Destination = M.Socksaddr{
		Fqdn: metadata.Domain,
		Port: metadata.Destination.Port,
	}
}

func (r *Router) applyOverrideAddressWithDomain(ctx context.Context, metadata *adapter.InboundContext) {
	mode := metadata.RouteOverrideAddressWithDomain
	if mode == C.RouteOverrideAddressWithDomainDefault || mode == C.RouteOverrideAddressWithDomainDisable || metadata.RouteOverrideAddressSet {
		return
	}
	if mode != C.RouteOverrideAddressWithDomainAlways && mode != C.RouteOverrideAddressWithDomainIfResolvable {
		return
	}
	if !isOverrideAddressWithDomainProtocol(metadata.Protocol) || !M.IsDomainName(metadata.Domain) {
		return
	}
	if mode == C.RouteOverrideAddressWithDomainAlways {
		overrideAddressWithDomain(metadata)
		return
	}
	if r.dns == nil {
		return
	}
	r.domainOverrideEvaluatorOnce.Do(func() {
		r.domainOverrideEvaluator = newDomainOverrideEvaluator()
	})
	domain := normalizeOverrideAddressDomain(metadata.Domain)
	if _, loaded := r.domainOverrideEvaluator.positive.Get(domain); loaded {
		overrideAddressWithDomain(metadata)
		return
	}
	if _, loaded := r.domainOverrideEvaluator.negative.Get(domain); loaded {
		return
	}
	addresses, err := r.dns.Lookup(adapter.WithContext(ctx, metadata), domain, adapter.DNSQueryOptions{
		CacheOnly: true,
		Quiet:     true,
	})
	if err == nil && len(addresses) > 0 {
		r.domainOverrideEvaluator.positive.Add(domain, struct{}{})
		overrideAddressWithDomain(metadata)
		return
	}
	r.warmOverrideAddressDomain(*metadata, domain)
}

func (r *Router) warmOverrideAddressDomain(metadata adapter.InboundContext, domain string) {
	if _, loaded := r.domainOverrideEvaluator.negative.Get(domain); loaded {
		return
	}
	r.domainOverrideEvaluator.group.DoChan(domain, func() (any, error) {
		if _, loaded := r.domainOverrideEvaluator.positive.Get(domain); loaded {
			return nil, nil
		}
		ctx := adapter.WithContext(r.ctx, &metadata)
		addresses, err := r.dns.Lookup(ctx, domain, adapter.DNSQueryOptions{Quiet: true})
		if err != nil || len(addresses) == 0 {
			r.domainOverrideEvaluator.negative.Add(domain, struct{}{})
			if err != nil {
				r.logger.DebugContext(ctx, "override address with domain DNS evaluation failed for ", domain, ": ", err)
			}
			return nil, err
		}
		r.domainOverrideEvaluator.positive.Add(domain, struct{}{})
		r.domainOverrideEvaluator.negative.Remove(domain)
		r.logger.DebugContext(ctx, "override address with domain DNS evaluation succeeded for ", domain)
		return nil, nil
	})
}
