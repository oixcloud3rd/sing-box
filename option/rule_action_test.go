package option

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestSniffOverrideDestinationUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var defaultAction RuleAction
	err := json.UnmarshalContext(context.Background(), []byte(`{"action":"sniff"}`), &defaultAction)
	require.NoError(t, err)
	require.Equal(t, C.SniffOverrideDestinationDefault, string(defaultAction.SniffOptions.OverrideDestination))

	testCases := []struct {
		name     string
		value    string
		expected string
	}{
		{"true", "true", C.SniffOverrideDestinationAlways},
		{"false", "false", C.SniffOverrideDestinationDisabled},
		{"disabled", `"disabled"`, C.SniffOverrideDestinationDisabled},
		{"always", `"always"`, C.SniffOverrideDestinationAlways},
		{"dns_evaluate", `"dns_evaluate"`, C.SniffOverrideDestinationDNSEvaluate},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var action RuleAction
			err := json.UnmarshalContext(context.Background(), []byte(`{"action":"sniff","override_destination":`+testCase.value+`}`), &action)
			require.NoError(t, err)
			require.Equal(t, testCase.expected, string(action.SniffOptions.OverrideDestination))
		})
	}
}

func TestSniffOverrideDestinationRejectsInvalidValue(t *testing.T) {
	t.Parallel()

	for _, value := range []string{`"invalid"`, "1", `{}`, `[]`} {
		var action RuleAction
		err := json.UnmarshalContext(context.Background(), []byte(`{"action":"sniff","override_destination":`+value+`}`), &action)
		require.Error(t, err, value)
	}
}

func TestSniffOverrideDestinationMarshalJSON(t *testing.T) {
	t.Parallel()

	action := RuleAction{
		Action: C.RuleActionTypeSniff,
		SniffOptions: RouteActionSniff{
			OverrideDestination: C.SniffOverrideDestinationAlways,
		},
	}
	content, err := json.Marshal(action)
	require.NoError(t, err)
	require.JSONEq(t, `{"action":"sniff","override_destination":"always"}`, string(content))

	action.SniffOptions.OverrideDestination = C.SniffOverrideDestinationDefault
	content, err = json.Marshal(action)
	require.NoError(t, err)
	require.JSONEq(t, `{"action":"sniff"}`, string(content))
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
