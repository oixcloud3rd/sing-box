package option

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func TestDestinationStrategyJSON(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name      string
		content   string
		strategy  string
		evaluator string
		ipOnly    bool
	}{
		{
			name:     "prefer destination addresses",
			content:  `"prefer_destination_addresses"`,
			strategy: C.DestinationStrategyPreferDestinationAddresses,
		},
		{
			name:     "prefer destination",
			content:  `"prefer_destination"`,
			strategy: C.DestinationStrategyPreferDestination,
		},
		{
			name:      "domain override",
			content:   `{"strategy":"prefer_destination","override_with_domain":{"evaluator":"dns-check","ip_only":true}}`,
			strategy:  C.DestinationStrategyPreferDestination,
			evaluator: "dns-check",
			ipOnly:    true,
		},
		{
			name:     "null override",
			content:  `{"strategy":"prefer_destination","override_with_domain":null}`,
			strategy: C.DestinationStrategyPreferDestination,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var strategy DestinationStrategy
			err := json.Unmarshal([]byte(testCase.content), &strategy)
			require.NoError(t, err)
			require.Equal(t, testCase.strategy, strategy.Strategy)
			if testCase.evaluator == "" {
				require.Nil(t, strategy.OverrideWithDomain)
			} else {
				require.Equal(t, testCase.evaluator, strategy.OverrideWithDomain.Evaluator)
				require.Equal(t, testCase.ipOnly, strategy.OverrideWithDomain.IPOnly)
			}
		})
	}
}

func TestDestinationStrategyRejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	for _, content := range []string{
		`"destination_addresses"`,
		`"destination"`,
		`"invalid"`,
		`{}`,
		`{"strategy":"prefer_destination","unknown":true}`,
		`{"strategy":"prefer_destination","override_with_domain":{}}`,
		`{"strategy":"prefer_destination","override_with_domain":{"evaluator":"dns-check","only_if_destination_is_ip":true}}`,
		`{"strategy":"prefer_destination_addresses","override_with_domain":{"evaluator":"dns-check"}}`,
	} {
		var strategy DestinationStrategy
		require.Error(t, json.Unmarshal([]byte(content), &strategy), content)
	}
}

func TestDestinationStrategyMarshalJSON(t *testing.T) {
	t.Parallel()

	strategy := DestinationStrategy{
		Strategy: C.DestinationStrategyPreferDestination,
		OverrideWithDomain: &OverrideWithDomainOptions{
			Evaluator: "dns-check",
			IPOnly:    true,
		},
	}
	content, err := json.Marshal(strategy)
	require.NoError(t, err)
	require.JSONEq(t, `{"strategy":"prefer_destination","override_with_domain":{"evaluator":"dns-check","ip_only":true}}`, string(content))

	content, err = json.Marshal(DefaultDestinationStrategy())
	require.NoError(t, err)
	require.JSONEq(t, `"prefer_destination_addresses"`, string(content))
}

func TestDomainEvaluatorValidation(t *testing.T) {
	t.Parallel()

	strategy := &DestinationStrategy{
		Strategy: C.DestinationStrategyPreferDestination,
		OverrideWithDomain: &OverrideWithDomainOptions{
			Evaluator: "dns-check",
		},
	}
	outboundOptions := &DirectOutboundOptions{}
	outboundOptions.DestinationStrategy = strategy
	require.NoError(t, checkDomainEvaluators(
		[]DomainEvaluatorOptions{{Tag: "dns-check"}},
		[]Outbound{{Options: outboundOptions}},
		nil,
	))
	require.Error(t, checkDomainEvaluators(nil, []Outbound{{Options: outboundOptions}}, nil))
	require.Error(t, checkDomainEvaluators([]DomainEvaluatorOptions{{}}, nil, nil))
	require.Error(t, checkDomainEvaluators([]DomainEvaluatorOptions{{Tag: "same"}, {Tag: "same"}}, nil, nil))
}

type destinationStrategyTestOutboundRegistry struct{}

func (destinationStrategyTestOutboundRegistry) OptionTypes() []string {
	return []string{C.TypeDirect, C.TypeSelector}
}

type destinationStrategyTestEndpointRegistry struct{}

func (destinationStrategyTestEndpointRegistry) OptionTypes() []string {
	return []string{C.TypeOpenVPNClient, C.TypeOpenVPNServer, C.TypeWireGuard}
}

func (destinationStrategyTestEndpointRegistry) CreateOptions(endpointType string) (any, bool) {
	switch endpointType {
	case C.TypeOpenVPNClient:
		return new(OpenVPNClientEndpointOptions), true
	case C.TypeOpenVPNServer:
		return new(OpenVPNServerEndpointOptions), true
	case C.TypeWireGuard:
		return new(WireGuardEndpointOptions), true
	default:
		return nil, false
	}
}

func (destinationStrategyTestOutboundRegistry) CreateOptions(outboundType string) (any, bool) {
	switch outboundType {
	case C.TypeDirect:
		return new(DirectOutboundOptions), true
	case C.TypeSelector:
		return new(SelectorOutboundOptions), true
	default:
		return nil, false
	}
}

func TestDestinationStrategyRejectsGroupOutbound(t *testing.T) {
	t.Parallel()

	ctx := service.ContextWith[OutboundOptionsRegistry](context.Background(), destinationStrategyTestOutboundRegistry{})
	var selector Outbound
	err := json.UnmarshalContext(ctx, []byte(`{
		"type":"selector",
		"outbounds":["direct"],
		"destination_strategy":"prefer_destination"
	}`), &selector)
	require.ErrorContains(t, err, "destination_strategy")

	var direct Outbound
	err = json.UnmarshalContext(ctx, []byte(`{
		"type":"direct",
		"destination_strategy":"prefer_destination"
	}`), &direct)
	require.NoError(t, err)
	directOptions := direct.Options.(*DirectOutboundOptions)
	require.Equal(t, C.DestinationStrategyPreferDestination, directOptions.DestinationStrategy.Strategy)
}

func TestDialAndDestinationStrategyFieldsCoexist(t *testing.T) {
	t.Parallel()

	ctx := service.ContextWith[OutboundOptionsRegistry](context.Background(), destinationStrategyTestOutboundRegistry{})
	var direct Outbound
	err := json.UnmarshalContext(ctx, []byte(`{
		"type":"direct",
		"tag":"direct-out",
		"detour":"upstream",
		"bind_interface":"en0",
		"destination_strategy":{
			"strategy":"prefer_destination",
			"override_with_domain":{
				"evaluator":"dns-check",
				"ip_only":true
			}
		}
	}`), &direct)
	require.NoError(t, err)
	directOptions := direct.Options.(*DirectOutboundOptions)
	require.Implements(t, (*DialerOptionsWrapper)(nil), directOptions)
	require.Implements(t, (*DestinationStrategyOptionsWrapper)(nil), directOptions)
	require.Equal(t, "upstream", directOptions.Detour)
	require.Equal(t, "en0", directOptions.BindInterface)
	require.Equal(t, C.DestinationStrategyPreferDestination, directOptions.DestinationStrategy.Strategy)
	require.Equal(t, "dns-check", directOptions.DestinationStrategy.OverrideWithDomain.Evaluator)

	content, err := direct.MarshalJSONContext(ctx)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"type":"direct",
		"tag":"direct-out",
		"detour":"upstream",
		"bind_interface":"en0",
		"destination_strategy":{
			"strategy":"prefer_destination",
			"override_with_domain":{
				"evaluator":"dns-check",
				"ip_only":true
			}
		}
	}`, string(content))
}

func TestEndpointDestinationStrategyPlacement(t *testing.T) {
	t.Parallel()

	require.Implements(t, (*DialerOptionsWrapper)(nil), new(OpenVPNClientEndpointOptions))
	require.Implements(t, (*DestinationStrategyOptionsWrapper)(nil), new(OpenVPNClientEndpointOptions))
	require.NotImplements(t, (*DestinationStrategyOptionsWrapper)(nil), new(OpenVPNEndpointOptions))
	require.NotImplements(t, (*DestinationStrategyOptionsWrapper)(nil), new(OpenVPNServerEndpointOptions))
	require.Implements(t, (*DialerOptionsWrapper)(nil), new(WireGuardEndpointOptions))
	require.Implements(t, (*DestinationStrategyOptionsWrapper)(nil), new(WireGuardEndpointOptions))

	ctx := service.ContextWith[EndpointOptionsRegistry](context.Background(), destinationStrategyTestEndpointRegistry{})
	var client Endpoint
	require.NoError(t, json.UnmarshalContext(ctx, []byte(`{"type":"openvpn-client","destination_strategy":"prefer_destination"}`), &client))
	require.Equal(t, C.DestinationStrategyPreferDestination, client.Options.(*OpenVPNClientEndpointOptions).DestinationStrategy.EffectiveStrategy())

	var server Endpoint
	require.ErrorContains(t, json.UnmarshalContext(ctx, []byte(`{"type":"openvpn-server","destination_strategy":"prefer_destination"}`), &server), "destination_strategy")
}
