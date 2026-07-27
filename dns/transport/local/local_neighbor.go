package local

import (
	"context"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/dns/transport/mdns"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

type PreferredDomainMatcher struct {
	ctx              context.Context
	logger           logger.ContextLogger
	hosts            *hosts.File
	neighborResolver adapter.NeighborResolver
	neighborSuffixes []string
}

func NewPreferredDomainMatcher(ctx context.Context, logger logger.ContextLogger, neighborDomains []string) (*PreferredDomainMatcher, error) {
	suffixes, err := buildNeighborMatchers(neighborDomains)
	if err != nil {
		return nil, err
	}
	return &PreferredDomainMatcher{
		ctx:              ctx,
		logger:           logger,
		neighborSuffixes: suffixes,
	}, nil
}

func (m *PreferredDomainMatcher) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateInitialize:
		defaultHosts, err := hosts.NewDefault()
		if err != nil {
			m.logger.Warn(err)
		} else {
			m.hosts = defaultHosts
		}
	case adapter.StartStateStart:
		router := service.FromContext[adapter.Router](m.ctx)
		if router != nil {
			m.neighborResolver = router.NeighborResolver()
		}
	}
	return nil
}

func (m *PreferredDomainMatcher) PreferredDomain(domain string) bool {
	canonical := mDNS.CanonicalName(domain)
	return len(m.lookupHosts(canonical)) > 0 || m.hasNeighborHost(canonical) || mdns.IsLocalDomain(canonical)
}

func (m *PreferredDomainMatcher) lookupHosts(domain string) []netip.Addr {
	if m.hosts == nil {
		return nil
	}
	return m.hosts.Lookup(dns.FqdnToDomain(domain))
}

func buildNeighborMatchers(domains []string) ([]string, error) {
	if len(domains) == 0 {
		return nil, nil
	}
	var suffixes []string
	for _, domain := range domains {
		if !strings.HasPrefix(domain, ".") {
			return nil, E.New("neighbor_domain entry must start with '.': ", domain)
		}
		suffixes = append(suffixes, mDNS.CanonicalName(domain))
	}
	return suffixes, nil
}

func (m *PreferredDomainMatcher) lookupNeighbor(message *mDNS.Msg) *mDNS.Msg {
	if m.neighborResolver == nil {
		return nil
	}
	question := message.Question[0]
	if question.Qtype != mDNS.TypeA && question.Qtype != mDNS.TypeAAAA {
		return nil
	}
	host := extractNeighborHost(mDNS.CanonicalName(question.Name), m.neighborSuffixes)
	if host == "" {
		return nil
	}
	addresses := m.neighborResolver.LookupAddresses(host)
	if len(addresses) == 0 {
		return nil
	}
	return dns.FixedResponse(message.Id, question, addresses, C.DefaultDNSTTL)
}

func (m *PreferredDomainMatcher) hasNeighborHost(domain string) bool {
	if m.neighborResolver == nil {
		return false
	}
	host := extractNeighborHost(domain, m.neighborSuffixes)
	if host == "" {
		return false
	}
	return len(m.neighborResolver.LookupAddresses(host)) > 0
}

func extractNeighborHost(canonical string, suffixes []string) string {
	for _, suffix := range suffixes {
		if !strings.HasSuffix(canonical, suffix) || len(canonical) <= len(suffix) {
			continue
		}
		host := canonical[:len(canonical)-len(suffix)]
		if !strings.ContainsRune(host, '.') {
			return host
		}
	}
	return ""
}
