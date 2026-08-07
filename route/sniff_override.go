package route

import (
	"context"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"

	"golang.org/x/sync/singleflight"
)

const (
	sniffOverrideCacheCapacity = 2048
	sniffOverrideNegativeTTL   = 10 * time.Second
)

type sniffOverrideEvaluator struct {
	positive *freelru.Cache[string, struct{}]
	negative *freelru.Cache[string, struct{}]
	group    singleflight.Group
}

func newSniffOverrideEvaluatorIfNeeded(rules []option.Rule) *sniffOverrideEvaluator {
	if !hasSniffOverrideDNSEvaluate(rules) {
		return nil
	}
	return newSniffOverrideEvaluator()
}

func hasSniffOverrideDNSEvaluate(rules []option.Rule) bool {
	for _, rule := range rules {
		var action option.RuleAction
		switch rule.Type {
		case "", C.RuleTypeDefault:
			action = rule.DefaultOptions.RuleAction
		case C.RuleTypeLogical:
			action = rule.LogicalOptions.RuleAction
			if hasSniffOverrideDNSEvaluate(rule.LogicalOptions.Rules) {
				return true
			}
		}
		if action.Action == C.RuleActionTypeSniff && action.SniffOptions.OverrideDestination == C.SniffOverrideDestinationDNSEvaluate {
			return true
		}
	}
	return false
}

func newSniffOverrideEvaluator() *sniffOverrideEvaluator {
	positive := common.Must1(freelru.New[string, struct{}](sniffOverrideCacheCapacity, maphash.NewHasher[string]().Hash32, true))
	negative := common.Must1(freelru.New[string, struct{}](sniffOverrideCacheCapacity, maphash.NewHasher[string]().Hash32, true))
	negative.SetLifetime(sniffOverrideNegativeTTL)
	return &sniffOverrideEvaluator{
		positive: positive,
		negative: negative,
	}
}

func isSniffOverrideProtocol(protocol string) bool {
	switch protocol {
	case C.ProtocolHTTP, C.ProtocolTLS, C.ProtocolQUIC:
		return true
	default:
		return false
	}
}

func normalizeSniffDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}

func setSniffDestination(metadata *adapter.InboundContext) {
	metadata.Destination = M.Socksaddr{
		Fqdn: metadata.Domain,
		Port: metadata.Destination.Port,
	}
}

func (r *Router) applySniffOverride(ctx context.Context, metadata *adapter.InboundContext, action *R.RuleActionSniff) {
	if action.OverrideDestination == C.SniffOverrideDestinationDefault || action.OverrideDestination == C.SniffOverrideDestinationDisabled ||
		!isSniffOverrideProtocol(metadata.Protocol) || !M.IsDomainName(metadata.Domain) {
		return
	}
	if action.OverrideDestination == C.SniffOverrideDestinationAlways {
		setSniffDestination(metadata)
		return
	}
	if action.OverrideDestination != C.SniffOverrideDestinationDNSEvaluate || r.dns == nil || r.sniffOverride == nil {
		return
	}
	domain := normalizeSniffDomain(metadata.Domain)
	if _, loaded := r.sniffOverride.positive.Get(domain); loaded {
		setSniffDestination(metadata)
		return
	}
	if _, loaded := r.sniffOverride.negative.Get(domain); loaded {
		return
	}
	addresses, err := r.dns.Lookup(adapter.WithContext(ctx, metadata), domain, adapter.DNSQueryOptions{
		CacheOnly: true,
		Quiet:     true,
	})
	if err == nil && len(addresses) > 0 {
		r.sniffOverride.positive.Add(domain, struct{}{})
		setSniffDestination(metadata)
		return
	}
	r.warmSniffOverrideDomain(*metadata, domain)
}

func (r *Router) warmSniffOverrideDomain(metadata adapter.InboundContext, domain string) {
	if _, loaded := r.sniffOverride.negative.Get(domain); loaded {
		return
	}
	r.sniffOverride.group.DoChan(domain, func() (any, error) {
		if _, loaded := r.sniffOverride.positive.Get(domain); loaded {
			return nil, nil
		}
		ctx := adapter.WithContext(r.ctx, &metadata)
		addresses, err := r.dns.Lookup(ctx, domain, adapter.DNSQueryOptions{Quiet: true})
		if err != nil || len(addresses) == 0 {
			r.sniffOverride.negative.Add(domain, struct{}{})
			if err != nil {
				r.logger.DebugContext(ctx, "sniff destination DNS evaluation failed for ", domain, ": ", err)
			}
			return nil, err
		}
		r.sniffOverride.positive.Add(domain, struct{}{})
		r.sniffOverride.negative.Remove(domain)
		r.logger.DebugContext(ctx, "sniff destination DNS evaluation succeeded for ", domain)
		return nil, nil
	})
}
