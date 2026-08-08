package option

import (
	"bytes"
	"context"
	stdjson "encoding/json"
	"fmt"
	"reflect"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/schema"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type OutboundOptionsRegistry interface {
	OptionTypes() []string
	CreateOptions(outboundType string) (any, bool)
}

type _Outbound struct {
	Type    string `json:"type"`
	Tag     string `json:"tag,omitempty"`
	Options any    `json:"-"`
}

type Outbound _Outbound

func (h *Outbound) MarshalJSONContext(ctx context.Context) ([]byte, error) {
	return badjson.MarshallObjectsContext(ctx, (*_Outbound)(h), h.Options)
}

func (h *Outbound) UnmarshalJSONContext(ctx context.Context, content []byte) error {
	err := json.UnmarshalContext(ctx, content, (*_Outbound)(h))
	if err != nil {
		return err
	}
	registry := service.FromContext[OutboundOptionsRegistry](ctx)
	if registry == nil {
		return E.New("missing outbound options registry in context")
	}
	switch h.Type {
	case C.TypeDNS:
		return E.New("dns outbound is deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use rule actions instead")
	}
	options, loaded := registry.CreateOptions(h.Type)
	if !loaded {
		return E.New("unknown outbound type: ", h.Type)
	}
	err = badjson.UnmarshallExcludedContext(ctx, content, (*_Outbound)(h), options)
	if err != nil {
		return err
	}
	if listenWrapper, isListen := options.(ListenOptionsWrapper); isListen {
		//nolint:staticcheck
		if listenWrapper.TakeListenOptions().InboundOptions != (InboundOptions{}) {
			return E.New("legacy inbound fields are deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use rule actions instead")
		}
	}
	h.Options = options
	return nil
}

func (h Outbound) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return builder.Define("Outbound", func() (*schema.Node, error) {
		registry := service.FromContext[OutboundOptionsRegistry](builder.Context())
		if registry == nil {
			return nil, E.New("missing outbound options registry in context")
		}
		return registryUnion(builder, registry, []string{C.TypeShadowsocksR, C.TypeWireGuard}, true)
	})
}

type DestinationStrategyOptionsWrapper interface {
	TakeDestinationStrategy() *DestinationStrategy
}

type DestinationStrategyOptions struct {
	DestinationStrategy *DestinationStrategy `json:"destination_strategy,omitempty"`
}

func (o *DestinationStrategyOptions) TakeDestinationStrategy() *DestinationStrategy {
	return o.DestinationStrategy
}

type DestinationStrategy struct {
	Strategy           string
	OverrideWithDomain *OverrideWithDomainOptions
}

type OverrideWithDomainOptions struct {
	Evaluator string `json:"evaluator" reference:"domain_evaluator"`
	IPOnly    bool   `json:"ip_only,omitempty"`
}

type DomainEvaluatorOptions struct {
	Tag    string `json:"tag"`
	Server string `json:"server,omitempty" reference:"dns_server"`
}

func (o DomainEvaluatorOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	node := schema.StrictObject()
	err := builder.FlattenStruct(node, reflect.TypeFor[DomainEvaluatorOptions]())
	if err != nil {
		return nil, err
	}
	node.Required = []string{"tag"}
	return node, nil
}

func checkDomainEvaluators(evaluators []DomainEvaluatorOptions, outbounds []Outbound, endpoints []Endpoint) error {
	evaluatorTags := make(map[string]bool, len(evaluators))
	for index, evaluator := range evaluators {
		if evaluator.Tag == "" {
			return E.New("missing domain evaluator tag at index ", index)
		}
		if evaluatorTags[evaluator.Tag] {
			return E.New("duplicate domain evaluator tag: ", evaluator.Tag)
		}
		evaluatorTags[evaluator.Tag] = true
	}
	validateStrategy := func(owner string, strategy *DestinationStrategy) error {
		if strategy == nil || strategy.OverrideWithDomain == nil {
			return nil
		}
		evaluatorTag := strategy.OverrideWithDomain.Evaluator
		if evaluatorTag == "" {
			return E.New(owner, " has override_with_domain without an evaluator")
		}
		if !evaluatorTags[evaluatorTag] {
			return E.New(owner, " references unknown domain evaluator: ", evaluatorTag)
		}
		return nil
	}
	for index := range outbounds {
		if err := validateStrategy(fmt.Sprint("outbound[", index, "]"), takeDestinationStrategy(outbounds[index].Options)); err != nil {
			return err
		}
	}
	for index := range endpoints {
		if err := validateStrategy(fmt.Sprint("endpoint[", index, "]"), takeDestinationStrategy(endpoints[index].Options)); err != nil {
			return err
		}
	}
	return nil
}

func takeDestinationStrategy(options any) *DestinationStrategy {
	wrapper, loaded := options.(DestinationStrategyOptionsWrapper)
	if !loaded {
		return nil
	}
	return wrapper.TakeDestinationStrategy()
}

type rawDestinationStrategy struct {
	Strategy           string                     `json:"strategy"`
	OverrideWithDomain *OverrideWithDomainOptions `json:"override_with_domain,omitempty"`
}

func DefaultDestinationStrategy() DestinationStrategy {
	return DestinationStrategy{Strategy: C.DestinationStrategyPreferDestinationAddresses}
}

func (s DestinationStrategy) EffectiveStrategy() string {
	if s.Strategy == "" {
		return C.DestinationStrategyPreferDestinationAddresses
	}
	return s.Strategy
}

func (s DestinationStrategy) MarshalJSON() ([]byte, error) {
	strategy := s.EffectiveStrategy()
	if s.OverrideWithDomain == nil {
		return json.Marshal(strategy)
	}
	return json.Marshal(rawDestinationStrategy{
		Strategy:           strategy,
		OverrideWithDomain: s.OverrideWithDomain,
	})
}

func (s *DestinationStrategy) UnmarshalJSON(content []byte) error {
	var stringValue string
	if err := json.Unmarshal(content, &stringValue); err == nil {
		if err = validateDestinationStrategy(stringValue, nil); err != nil {
			return err
		}
		s.Strategy = stringValue
		s.OverrideWithDomain = nil
		return nil
	}
	var raw rawDestinationStrategy
	decoder := stdjson.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return err
	}
	if raw.Strategy == "" {
		return E.New("missing destination strategy")
	}
	if err := validateDestinationStrategy(raw.Strategy, raw.OverrideWithDomain); err != nil {
		return err
	}
	s.Strategy = raw.Strategy
	s.OverrideWithDomain = raw.OverrideWithDomain
	return nil
}

func validateDestinationStrategy(strategy string, overrideWithDomain *OverrideWithDomainOptions) error {
	if overrideWithDomain != nil && overrideWithDomain.Evaluator == "" {
		return E.New("missing override_with_domain.evaluator")
	}
	switch strategy {
	case C.DestinationStrategyPreferDestinationAddresses:
		if overrideWithDomain != nil {
			return E.New("override_with_domain is only available with prefer_destination")
		}
	case C.DestinationStrategyPreferDestination:
	default:
		return E.New("unknown destination strategy: ", strategy)
	}
	return nil
}

func (s DestinationStrategy) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return builder.Define("DestinationStrategy", func() (*schema.Node, error) {
		overrideObject := schema.StrictObject()
		overrideObject.Properties.Put("evaluator", schema.TagReferenceNode("domain_evaluator"))
		overrideObject.Properties.Put("ip_only", schema.BooleanNode())
		overrideObject.Required = []string{"evaluator"}
		preferAddressesObject := schema.StrictObject()
		preferAddressesObject.Properties.Put("strategy", schema.StringConst(C.DestinationStrategyPreferDestinationAddresses))
		preferAddressesObject.Required = []string{"strategy"}
		preferDestinationObject := schema.StrictObject()
		preferDestinationObject.Properties.Put("strategy", schema.StringConst(C.DestinationStrategyPreferDestination))
		preferDestinationObject.Properties.Put("override_with_domain", schema.AnyOf(overrideObject, &schema.Node{Type: "null"}))
		preferDestinationObject.Required = []string{"strategy"}
		return schema.AnyOf(
			schema.StringEnum(
				C.DestinationStrategyPreferDestinationAddresses,
				C.DestinationStrategyPreferDestination,
			),
			preferAddressesObject,
			preferDestinationObject,
		), nil
	})
}

type DialerOptionsWrapper interface {
	TakeDialerOptions() DialerOptions
	ReplaceDialerOptions(options DialerOptions)
}

type DialerOptions struct {
	Detour string `json:"detour,omitempty" reference:"outbound"`
	AbstractDialerOptions
}

type AbstractDialerOptions struct {
	BindInterface              string                            `json:"bind_interface,omitempty"`
	Inet4BindAddress           *badoption.Addr                   `json:"inet4_bind_address,omitempty"`
	Inet6BindAddress           *badoption.Addr                   `json:"inet6_bind_address,omitempty"`
	BindAddressNoPort          bool                              `json:"bind_address_no_port,omitempty"`
	ProtectPath                string                            `json:"protect_path,omitempty"`
	RoutingMark                FwMark                            `json:"routing_mark,omitempty"`
	ReuseAddr                  bool                              `json:"reuse_addr,omitempty"`
	NetNs                      string                            `json:"netns,omitempty" reference:"network_namespace"`
	ConnectTimeout             badoption.Duration                `json:"connect_timeout,omitempty"`
	TCPFastOpen                bool                              `json:"tcp_fast_open,omitempty"`
	TCPMultiPath               bool                              `json:"tcp_multi_path,omitempty"`
	DisableTCPKeepAlive        bool                              `json:"disable_tcp_keep_alive,omitempty"`
	TCPKeepAlive               badoption.Duration                `json:"tcp_keep_alive,omitempty"`
	TCPKeepAliveInterval       badoption.Duration                `json:"tcp_keep_alive_interval,omitempty"`
	TCPKeepAliveSystemDefaults bool                              `json:"-"`
	UDPBindPort                uint16                            `json:"-"`
	UDPFragment                *bool                             `json:"udp_fragment,omitempty"`
	UDPFragmentDefault         bool                              `json:"-"`
	DomainResolver             *DomainResolveOptions             `json:"domain_resolver,omitempty"`
	NetworkStrategy            *NetworkStrategy                  `json:"network_strategy,omitempty"`
	NetworkType                badoption.Listable[InterfaceType] `json:"network_type,omitempty"`
	FallbackNetworkType        badoption.Listable[InterfaceType] `json:"fallback_network_type,omitempty"`
	FallbackDelay              badoption.Duration                `json:"fallback_delay,omitempty"`

	// Deprecated: migrated to domain resolver
	DomainStrategy DomainStrategy `json:"domain_strategy,omitempty" schema:"omit"`
}

type _DomainResolveOptions struct {
	Server                 string                `json:"server" reference:"dns_server"`
	Timeout                badoption.Duration    `json:"timeout,omitempty"`
	Strategy               DomainStrategy        `json:"strategy,omitempty"`
	DisableCache           bool                  `json:"disable_cache,omitempty"`
	DisableOptimisticCache bool                  `json:"disable_optimistic_cache,omitempty"`
	RewriteTTL             *uint32               `json:"rewrite_ttl,omitempty"`
	ClientSubnet           *badoption.Prefixable `json:"client_subnet,omitempty"`
}

type DomainResolveOptions _DomainResolveOptions

func (o DomainResolveOptions) MarshalJSON() ([]byte, error) {
	if o.Server == "" {
		return []byte("{}"), nil
	} else if o.Strategy == DomainStrategy(C.DomainStrategyAsIS) &&
		o.Timeout == 0 &&
		!o.DisableCache &&
		!o.DisableOptimisticCache &&
		o.RewriteTTL == nil &&
		o.ClientSubnet == nil {
		return json.Marshal(o.Server)
	} else {
		return json.Marshal((_DomainResolveOptions)(o))
	}
}

func (o *DomainResolveOptions) UnmarshalJSON(bytes []byte) error {
	var stringValue string
	err := json.Unmarshal(bytes, &stringValue)
	if err == nil {
		o.Server = stringValue
		return nil
	}
	err = json.Unmarshal(bytes, (*_DomainResolveOptions)(o))
	if err != nil {
		return err
	}
	if o.Server == "" {
		return E.New("empty domain_resolver.server")
	}
	return nil
}

func (o DomainResolveOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return builder.Define("DomainResolver", func() (*schema.Node, error) {
		objectForm := schema.StrictObject()
		err := builder.FlattenStruct(objectForm, reflect.TypeFor[DomainResolveOptions]())
		if err != nil {
			return nil, err
		}
		objectForm.Required = []string{"server"}
		return schema.AnyOf(schema.TagReferenceNode("dns_server"), objectForm), nil
	})
}

func (o *DialerOptions) TakeDialerOptions() DialerOptions {
	return *o
}

func (o *DialerOptions) ReplaceDialerOptions(options DialerOptions) {
	*o = options
}

type ServerOptionsWrapper interface {
	TakeServerOptions() ServerOptions
	ReplaceServerOptions(options ServerOptions)
}

type ServerOptions struct {
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
}

func (o ServerOptions) Build() M.Socksaddr {
	return M.ParseSocksaddrHostPort(o.Server, o.ServerPort)
}

func (o ServerOptions) ServerIsDomain() bool {
	return o.Build().IsDomain()
}

func (o *ServerOptions) TakeServerOptions() ServerOptions {
	return *o
}

func (o *ServerOptions) ReplaceServerOptions(options ServerOptions) {
	*o = options
}
