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
		expected string
	}{
		{"true", "true", C.RouteOverrideAddressWithDomainAlways},
		{"false", "false", C.RouteOverrideAddressWithDomainDefault},
		{"empty", `""`, C.RouteOverrideAddressWithDomainDefault},
		{"disable", `"disable"`, C.RouteOverrideAddressWithDomainDisable},
		{"always", `"always"`, C.RouteOverrideAddressWithDomainAlways},
		{"if_resolvable", `"if_resolvable"`, C.RouteOverrideAddressWithDomainIfResolvable},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var action RuleAction
			err := json.UnmarshalContext(context.Background(), []byte(`{"action":"route","outbound":"direct","override_address_with_domain":`+testCase.value+`}`), &action)
			require.NoError(t, err)
			require.Equal(t, testCase.expected, string(action.RouteOptions.OverrideAddressWithDomain))
		})
	}
}

func TestRouteOverrideAddressWithDomainActions(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		content string
		mode    func(RuleAction) RouteOverrideAddressWithDomain
	}{
		{"route", `{"action":"route","outbound":"direct","override_address_with_domain":"always"}`, func(action RuleAction) RouteOverrideAddressWithDomain {
			return action.RouteOptions.OverrideAddressWithDomain
		}},
		{"route-options", `{"action":"route-options","override_address_with_domain":"always"}`, func(action RuleAction) RouteOverrideAddressWithDomain {
			return action.RouteOptionsOptions.OverrideAddressWithDomain
		}},
		{"bypass", `{"action":"bypass","outbound":"direct","override_address_with_domain":"always"}`, func(action RuleAction) RouteOverrideAddressWithDomain {
			return action.BypassOptions.OverrideAddressWithDomain
		}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var action RuleAction
			err := json.UnmarshalContext(context.Background(), []byte(testCase.content), &action)
			require.NoError(t, err)
			require.Equal(t, RouteOverrideAddressWithDomain(C.RouteOverrideAddressWithDomainAlways), testCase.mode(action))
		})
	}
}

func TestRouteOverrideAddressWithDomainRejectsInvalidValue(t *testing.T) {
	t.Parallel()

	for _, value := range []string{`"skip"`, `"invalid"`, "null", "1", `{}`, `[]`} {
		var action RuleAction
		err := json.UnmarshalContext(context.Background(), []byte(`{"action":"route","outbound":"direct","override_address_with_domain":`+value+`}`), &action)
		require.Error(t, err, value)
	}

	var sniffAction RuleAction
	err := json.UnmarshalContext(context.Background(), []byte(`{"action":"sniff","override_destination":true}`), &sniffAction)
	require.ErrorContains(t, err, "unknown field")
}

func TestRouteOverrideAddressWithDomainMarshalJSON(t *testing.T) {
	t.Parallel()

	action := RuleAction{
		Action: C.RuleActionTypeRoute,
		RouteOptions: RouteActionOptions{
			Outbound: "direct",
			RawRouteOptionsActionOptions: RawRouteOptionsActionOptions{
				OverrideAddressWithDomain: C.RouteOverrideAddressWithDomainAlways,
			},
		},
	}
	content, err := json.Marshal(action)
	require.NoError(t, err)
	require.JSONEq(t, `{"outbound":"direct","override_address_with_domain":"always"}`, string(content))

	action.RouteOptions.OverrideAddressWithDomain = C.RouteOverrideAddressWithDomainDefault
	content, err = json.Marshal(action)
	require.NoError(t, err)
	require.JSONEq(t, `{"outbound":"direct"}`, string(content))
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
