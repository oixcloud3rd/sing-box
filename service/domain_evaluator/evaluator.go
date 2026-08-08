package domainevaluator

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"

	"golang.org/x/sync/singleflight"
)

const (
	cacheCapacity = 2048
	negativeTTL   = 10 * time.Second
)

var (
	_ adapter.DomainEvaluator = (*Evaluator)(nil)
	_ adapter.Lifecycle       = (*Evaluator)(nil)
)

type Evaluator struct {
	ctx             context.Context
	cancel          context.CancelFunc
	logger          log.ContextLogger
	dns             adapter.DNSRouter
	dnsTransport    adapter.DNSTransportManager
	tag             string
	server          string
	transportAccess sync.RWMutex
	transport       adapter.DNSTransport
	positive        *freelru.Cache[string, struct{}]
	negative        *freelru.Cache[string, struct{}]
	group           singleflight.Group
}

func New(
	ctx context.Context,
	logger log.ContextLogger,
	dnsRouter adapter.DNSRouter,
	dnsTransportManager adapter.DNSTransportManager,
	options option.DomainEvaluatorOptions,
) *Evaluator {
	evaluatorCtx, cancel := context.WithCancel(ctx)
	positive := common.Must1(freelru.New[string, struct{}](cacheCapacity, maphash.NewHasher[string]().Hash32, true))
	negative := common.Must1(freelru.New[string, struct{}](cacheCapacity, maphash.NewHasher[string]().Hash32, true))
	negative.SetLifetime(negativeTTL)
	return &Evaluator{
		ctx:          evaluatorCtx,
		cancel:       cancel,
		logger:       logger,
		dns:          dnsRouter,
		dnsTransport: dnsTransportManager,
		tag:          options.Tag,
		server:       options.Server,
		positive:     positive,
		negative:     negative,
	}
}

func (e *Evaluator) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart || e.server == "" {
		return nil
	}
	if e.dnsTransport == nil {
		return E.New("domain evaluator[", e.tag, "] DNS server not found: ", e.server)
	}
	transport, loaded := e.dnsTransport.Transport(e.server)
	if !loaded {
		return E.New("domain evaluator[", e.tag, "] DNS server not found: ", e.server)
	}
	e.transportAccess.Lock()
	e.transport = transport
	e.transportAccess.Unlock()
	return nil
}

func (e *Evaluator) Close() error {
	e.cancel()
	return nil
}

func (e *Evaluator) Tag() string {
	return e.tag
}

func (e *Evaluator) Evaluate(ctx context.Context, metadata *adapter.InboundContext, domain string) bool {
	if e.dns == nil {
		return false
	}
	if _, loaded := e.positive.Get(domain); loaded {
		return true
	}
	if _, loaded := e.negative.Get(domain); loaded {
		return false
	}
	transport, loaded := e.selectedTransport()
	if !loaded {
		return false
	}
	addresses, err := e.dns.Lookup(adapter.WithContext(ctx, metadata), domain, adapter.DNSQueryOptions{
		Transport: transport,
		CacheOnly: true,
		Quiet:     true,
	})
	if err == nil && len(addresses) > 0 {
		e.positive.Add(domain, struct{}{})
		return true
	}
	e.warm(*metadata, domain, transport)
	return false
}

func (e *Evaluator) selectedTransport() (adapter.DNSTransport, bool) {
	if e.server == "" {
		return nil, true
	}
	e.transportAccess.RLock()
	transport := e.transport
	e.transportAccess.RUnlock()
	return transport, transport != nil
}

func (e *Evaluator) warm(metadata adapter.InboundContext, domain string, transport adapter.DNSTransport) {
	if _, loaded := e.negative.Get(domain); loaded {
		return
	}
	e.group.DoChan(domain, func() (any, error) {
		if _, loaded := e.positive.Get(domain); loaded {
			return nil, nil
		}
		ctx := adapter.WithContext(e.ctx, &metadata)
		addresses, err := e.dns.Lookup(ctx, domain, adapter.DNSQueryOptions{
			Transport: transport,
			Quiet:     true,
		})
		if err != nil || len(addresses) == 0 {
			e.negative.Add(domain, struct{}{})
			if err != nil {
				e.logger.DebugContext(ctx, "domain evaluator[", e.tag, "] failed for ", domain, ": ", err)
			}
			return nil, err
		}
		e.positive.Add(domain, struct{}{})
		e.negative.Remove(domain)
		e.logger.DebugContext(ctx, "domain evaluator[", e.tag, "] succeeded for ", domain)
		return nil, nil
	})
}
