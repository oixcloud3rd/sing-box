package option

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestRouteOverrideAddressWithDomainUnmarshalJSON(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		value    string
		expected RouteOverrideAddressWithDomainCondition
	}{
		{"true", "true", RouteOverrideAddressWithDomainCondition(C.RouteOverrideAddressWithDomainAlways)},
		{"false", "false", RouteOverrideAddressWithDomainCondition(C.RouteOverrideAddressWithDomainDefault)},
		{"empty", `""`, RouteOverrideAddressWithDomainCondition(C.RouteOverrideAddressWithDomainDefault)},
		{"disable", `"disable"`, RouteOverrideAddressWithDomainCondition(C.RouteOverrideAddressWithDomainDisable)},
		{"always", `"always"`, RouteOverrideAddressWithDomainCondition(C.RouteOverrideAddressWithDomainAlways)},
		{"if_resolvable", `"if_resolvable"`, RouteOverrideAddressWithDomainCondition(C.RouteOverrideAddressWithDomainIfResolvable)},
		{"object", `{"condition":"always"}`, RouteOverrideAddressWithDomainCondition(C.RouteOverrideAddressWithDomainAlways)},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var action RuleAction
			err := json.UnmarshalContext(context.Background(), []byte(`{"action":"route","outbound":"direct","override_address_with_domain":`+testCase.value+`}`), &action)
			require.NoError(t, err)
			require.Equal(t, testCase.expected, action.RouteOptions.OverrideAddressWithDomain.Condition)
		})
	}
}

func TestRouteOverrideAddressWithDomainActions(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		content string
		options func(RuleAction) RouteOverrideAddressWithDomainOptions
	}{
		{"route", `{"action":"route","outbound":"direct","override_address_with_domain":{"condition":"always","scope":{"domain":false}}}`, func(action RuleAction) RouteOverrideAddressWithDomainOptions {
			return action.RouteOptions.OverrideAddressWithDomain
		}},
		{"route-options", `{"action":"route-options","override_address_with_domain":{"condition":"always","scope":{"domain":false}}}`, func(action RuleAction) RouteOverrideAddressWithDomainOptions {
			return action.RouteOptionsOptions.OverrideAddressWithDomain
		}},
		{"bypass", `{"action":"bypass","outbound":"direct","override_address_with_domain":{"condition":"always","scope":{"domain":false}}}`, func(action RuleAction) RouteOverrideAddressWithDomainOptions {
			return action.BypassOptions.OverrideAddressWithDomain
		}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var action RuleAction
			err := json.UnmarshalContext(context.Background(), []byte(testCase.content), &action)
			require.NoError(t, err)
			options := testCase.options(action)
			require.Equal(t, RouteOverrideAddressWithDomainCondition(C.RouteOverrideAddressWithDomainAlways), options.Condition)
			require.NotNil(t, options.Scope)
			require.NotNil(t, options.Scope.Domain)
			require.False(t, *options.Scope.Domain)
			require.Nil(t, options.Scope.IP)
		})
	}
}

func TestRouteOverrideAddressWithDomainRejectsInvalidValue(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		`"skip"`,
		`"invalid"`,
		"null",
		"1",
		`[]`,
		`{"condition":"invalid"}`,
		`{"unknown":true}`,
		`{"scope":{"unknown":true}}`,
		`{"scope":{"domain":"true"}}`,
	} {
		var action RuleAction
		err := json.UnmarshalContext(context.Background(), []byte(`{"action":"route","outbound":"direct","override_address_with_domain":`+value+`}`), &action)
		require.Error(t, err, value)
	}

	var emptyAction RuleAction
	err := json.UnmarshalContext(context.Background(), []byte(`{"action":"route-options","override_address_with_domain":{"scope":{}}}`), &emptyAction)
	require.ErrorContains(t, err, "empty route option action")

	var sniffAction RuleAction
	err = json.UnmarshalContext(context.Background(), []byte(`{"action":"sniff","override_destination":true}`), &sniffAction)
	require.ErrorContains(t, err, "unknown field")
}

func TestRouteOverrideAddressWithDomainMarshalJSON(t *testing.T) {
	t.Parallel()

	domainScope := false
	ipScope := true
	action := RuleAction{
		Action: C.RuleActionTypeRoute,
		RouteOptions: RouteActionOptions{
			Outbound: "direct",
			RawRouteOptionsActionOptions: RawRouteOptionsActionOptions{
				OverrideAddressWithDomain: RouteOverrideAddressWithDomainOptions{
					Condition: RouteOverrideAddressWithDomainCondition(C.RouteOverrideAddressWithDomainAlways),
					Scope: &RouteOverrideAddressWithDomainScopeOptions{
						Domain: &domainScope,
						IP:     &ipScope,
					},
				},
			},
		},
	}
	content, err := json.Marshal(action)
	require.NoError(t, err)
	require.JSONEq(t, `{"outbound":"direct","override_address_with_domain":{"condition":"always","scope":{"domain":false,"ip":true}}}`, string(content))

	action.RouteOptions.OverrideAddressWithDomain = RouteOverrideAddressWithDomainOptions{}
	content, err = json.Marshal(action)
	require.NoError(t, err)
	require.JSONEq(t, `{"outbound":"direct"}`, string(content))

	err = json.UnmarshalContext(context.Background(), []byte(`{"action":"route","outbound":"direct","override_address_with_domain":"always"}`), &action)
	require.NoError(t, err)
	content, err = json.Marshal(action)
	require.NoError(t, err)
	require.JSONEq(t, `{"outbound":"direct","override_address_with_domain":{"condition":"always"}}`, string(content))
}

func TestRouteResolveRouteOnlyJSON(t *testing.T) {
	t.Parallel()

	var action RuleAction
	err := json.UnmarshalContext(context.Background(), []byte(`{"action":"resolve"}`), &action)
	require.NoError(t, err)
	require.False(t, action.ResolveOptions.RouteOnly)
	content, err := json.Marshal(action)
	require.NoError(t, err)
	require.JSONEq(t, `{"action":"resolve"}`, string(content))

	err = json.UnmarshalContext(context.Background(), []byte(`{"action":"resolve","route_only":true}`), &action)
	require.NoError(t, err)
	require.True(t, action.ResolveOptions.RouteOnly)

	content, err = json.Marshal(action)
	require.NoError(t, err)
	require.JSONEq(t, `{"action":"resolve","route_only":true}`, string(content))
}

func TestDNSRuleActionRespondUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var action DNSRuleAction
	err := json.UnmarshalContext(context.Background(), []byte(`{"action":"respond"}`), &action)
	require.NoError(t, err)
	require.Equal(t, C.RuleActionTypeRespond, action.Action)
	require.Equal(t, DNSRouteActionOptions{}, action.RouteOptions)
}

func TestDNSRuleActionRespondRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	var action DNSRuleAction
	err := json.UnmarshalContext(context.Background(), []byte(`{"action":"respond","disable_cache":true}`), &action)
	require.ErrorContains(t, err, "unknown field")
}
