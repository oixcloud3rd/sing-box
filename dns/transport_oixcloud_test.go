package dns

import (
	"context"
	"crypto/ed25519"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type fakeOIXCloudTransport struct {
	message       *mDNS.Msg
	response      func(message *mDNS.Msg) *mDNS.Msg
	exchangeError error
	startStage    adapter.StartStage
	startCount    int
	closeCount    int
	resetCount    int
}

func (t *fakeOIXCloudTransport) Type() string {
	return "fake"
}

func (t *fakeOIXCloudTransport) Tag() string {
	return "fake-tag"
}

func (t *fakeOIXCloudTransport) Dependencies() []string {
	return []string{"dependency"}
}

func (t *fakeOIXCloudTransport) Start(stage adapter.StartStage) error {
	t.startStage = stage
	t.startCount++
	return nil
}

func (t *fakeOIXCloudTransport) Close() error {
	t.closeCount++
	return nil
}

func (t *fakeOIXCloudTransport) Reset() {
	t.resetCount++
}

func (t *fakeOIXCloudTransport) Exchange(_ context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.message = message
	if t.exchangeError != nil {
		return nil, t.exchangeError
	}
	if t.response != nil {
		return t.response(message), nil
	}
	return message.Copy(), nil
}

func (t *fakeOIXCloudTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	callback(t.Exchange(ctx, message))
}

func testOIXCloudDNSAuthPrivateKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func testOIXCloudTransport(upstream adapter.DNSTransport, unixTime int64) *oixCloudTransport {
	return &oixCloudTransport{
		DNSTransport: upstream,
		logger:       log.NewNOPFactory().Logger(),
		privateKey:   testOIXCloudDNSAuthPrivateKey(),
		timeFunc: func() time.Time {
			return time.Unix(unixTime, 0)
		},
	}
}

func TestParseOIXCloudDNSAuthPrivateKey(t *testing.T) {
	t.Parallel()

	seed := testOIXCloudDNSAuthPrivateKey().Seed()
	for _, encoded := range []string{
		base64.StdEncoding.EncodeToString(seed),
		base64.RawStdEncoding.EncodeToString(seed),
	} {
		privateKey, err := parseOIXCloudDNSAuthPrivateKey(encoded)
		require.NoError(t, err)
		require.Equal(t, testOIXCloudDNSAuthPrivateKey(), privateKey)
	}
	_, err := parseOIXCloudDNSAuthPrivateKey("")
	require.EqualError(t, err, "missing oixCloud DNS auth private key: inject OIXCLOUD_DNS_AUTH_PRIVATE_KEY at build time")
	_, err = parseOIXCloudDNSAuthPrivateKey("not-base64!")
	require.ErrorContains(t, err, "decode oixCloud DNS auth private key")
	_, err = parseOIXCloudDNSAuthPrivateKey(base64.StdEncoding.EncodeToString([]byte("short")))
	require.EqualError(t, err, "invalid oixCloud DNS auth private key seed length: got 5, want 32")
}

func TestOIXCloudTransportRegistryWrapping(t *testing.T) {
	originalPrivateKey := C.OIXCloudDNSAuthPrivateKey
	t.Cleanup(func() { C.OIXCloudDNSAuthPrivateKey = originalPrivateKey })

	upstream := &fakeOIXCloudTransport{}
	registry := NewTransportRegistry()
	RegisterTransport[option.RemoteDNSServerOptions](registry, "test", func(context.Context, log.ContextLogger, string, option.RemoteDNSServerOptions) (adapter.DNSTransport, error) {
		return upstream, nil
	})

	plain, err := registry.CreateDNSTransport(context.Background(), nil, "plain", "test", &option.RemoteDNSServerOptions{})
	require.NoError(t, err)
	require.Same(t, upstream, plain)

	C.OIXCloudDNSAuthPrivateKey = ""
	_, err = registry.CreateDNSTransport(context.Background(), nil, "signed", "test", &option.RemoteDNSServerOptions{OIXCloud: true})
	require.ErrorContains(t, err, "missing oixCloud DNS auth private key")

	C.OIXCloudDNSAuthPrivateKey = base64.StdEncoding.EncodeToString(testOIXCloudDNSAuthPrivateKey().Seed())
	signed, err := registry.CreateDNSTransport(context.Background(), nil, "signed", "test", &option.RemoteDNSServerOptions{OIXCloud: true})
	require.NoError(t, err)
	require.IsType(t, &oixCloudTransport{}, signed)
}

func TestOIXCloudTokenizeHost(t *testing.T) {
	t.Parallel()

	transport := testOIXCloudTransport(&fakeOIXCloudTransport{}, 1700000000)
	signed, err := transport.tokenizeHost("Example.COM.")
	require.NoError(t, err)
	require.Equal(t, "hfbbr4ykfgo2u76ahw3ecur5mnygaa4764kn6aqcgx7how7mhopq.rbjitbn7b6svs4ryz4cu76p5pjfekczt3mygj6q23wjfsfvs3uaq.example.com.", signed)

	labels := mDNS.SplitDomainName(signed)
	require.Len(t, labels, 4)
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	first, err := encoding.DecodeString(strings.ToUpper(labels[0]))
	require.NoError(t, err)
	second, err := encoding.DecodeString(strings.ToUpper(labels[1]))
	require.NoError(t, err)
	signature := append(first, second...)
	publicKey := testOIXCloudDNSAuthPrivateKey().Public().(ed25519.PublicKey)
	require.True(t, ed25519.Verify(publicKey, oixCloudAuthMessage("example.com", 1700000000/oixCloudWindowSeconds), signature))

	transport.timeFunc = func() time.Time { return time.Unix(1700000099, 0) }
	sameWindow, err := transport.tokenizeHost("example.com")
	require.NoError(t, err)
	require.Equal(t, signed, sameWindow)
	transport.timeFunc = func() time.Time { return time.Unix(1700000300, 0) }
	nextWindow, err := transport.tokenizeHost("example.com")
	require.NoError(t, err)
	require.NotEqual(t, signed, nextWindow)

	root, err := transport.tokenizeHost(".")
	require.NoError(t, err)
	require.Equal(t, ".", root)
}

func TestOIXCloudExchangeAndRestore(t *testing.T) {
	t.Parallel()

	upstream := &fakeOIXCloudTransport{}
	upstream.response = func(message *mDNS.Msg) *mDNS.Msg {
		signed := message.Question[0].Name
		header := func(recordType uint16) mDNS.RR_Header {
			return mDNS.RR_Header{Name: signed, Rrtype: recordType, Class: mDNS.ClassINET, Ttl: 60}
		}
		return &mDNS.Msg{
			MsgHdr:   mDNS.MsgHdr{Id: message.Id, Response: true},
			Question: append([]mDNS.Question(nil), message.Question...),
			Answer: []mDNS.RR{
				&mDNS.A{Hdr: header(mDNS.TypeA)},
				&mDNS.CNAME{Hdr: header(mDNS.TypeCNAME), Target: signed},
				&mDNS.PTR{Hdr: header(mDNS.TypePTR), Ptr: signed},
				&mDNS.MX{Hdr: header(mDNS.TypeMX), Mx: signed},
				&mDNS.SRV{Hdr: header(mDNS.TypeSRV), Target: signed},
			},
			Ns: []mDNS.RR{
				&mDNS.NS{Hdr: header(mDNS.TypeNS), Ns: signed},
				&mDNS.SOA{Hdr: header(mDNS.TypeSOA), Ns: signed, Mbox: signed},
			},
			Extra: []mDNS.RR{
				&mDNS.SVCB{Hdr: header(mDNS.TypeSVCB), Target: signed},
				&mDNS.HTTPS{SVCB: mDNS.SVCB{Hdr: header(mDNS.TypeHTTPS), Target: signed}},
			},
		}
	}
	transport := testOIXCloudTransport(upstream, 1700000000)
	request := new(mDNS.Msg)
	request.SetQuestion("Example.COM.", mDNS.TypeA)
	response, err := transport.Exchange(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, "Example.COM.", request.Question[0].Name)
	require.NotEqual(t, request.Question[0].Name, upstream.message.Question[0].Name)
	require.Equal(t, strings.ToLower(upstream.message.Question[0].Name), upstream.message.Question[0].Name)
	require.Equal(t, "Example.COM.", response.Question[0].Name)

	for _, records := range [][]mDNS.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range records {
			require.Equal(t, "Example.COM.", record.Header().Name)
		}
	}
	require.Equal(t, "Example.COM.", response.Answer[1].(*mDNS.CNAME).Target)
	require.Equal(t, "Example.COM.", response.Answer[2].(*mDNS.PTR).Ptr)
	require.Equal(t, "Example.COM.", response.Answer[3].(*mDNS.MX).Mx)
	require.Equal(t, "Example.COM.", response.Answer[4].(*mDNS.SRV).Target)
	require.Equal(t, "Example.COM.", response.Ns[0].(*mDNS.NS).Ns)
	require.Equal(t, "Example.COM.", response.Ns[1].(*mDNS.SOA).Ns)
	require.Equal(t, "Example.COM.", response.Ns[1].(*mDNS.SOA).Mbox)
	require.Equal(t, "Example.COM.", response.Extra[0].(*mDNS.SVCB).Target)
	require.Equal(t, "Example.COM.", response.Extra[1].(*mDNS.HTTPS).Target)
}

func TestOIXCloudExchangeAsync(t *testing.T) {
	t.Parallel()

	upstream := &fakeOIXCloudTransport{}
	transport := testOIXCloudTransport(upstream, 1700000000)
	request := new(mDNS.Msg)
	request.SetQuestion("async.example.", mDNS.TypeAAAA)
	called := false
	transport.ExchangeAsync(context.Background(), request, func(response *mDNS.Msg, err error) {
		called = true
		require.NoError(t, err)
		require.Equal(t, "async.example.", response.Question[0].Name)
	})
	require.True(t, called)
	require.Equal(t, "async.example.", request.Question[0].Name)
	require.NotEqual(t, request.Question[0].Name, upstream.message.Question[0].Name)
}

func TestOIXCloudStrictFailures(t *testing.T) {
	t.Parallel()

	upstream := &fakeOIXCloudTransport{}
	transport := testOIXCloudTransport(upstream, 1700000000)
	_, err := transport.Exchange(context.Background(), nil)
	require.EqualError(t, err, "nil oixCloud DNS request")
	require.Nil(t, upstream.message)

	request := new(mDNS.Msg)
	request.SetQuestion(strings.Repeat("a", 63)+"."+strings.Repeat("b", 63)+"."+strings.Repeat("c", 30)+".", mDNS.TypeA)
	_, err = transport.Exchange(context.Background(), request)
	require.ErrorContains(t, err, "signed domain exceeds DNS limits")
	require.Nil(t, upstream.message)

	upstream.exchangeError = errors.New("upstream failure")
	request.SetQuestion("example.com.", mDNS.TypeA)
	_, err = transport.Exchange(context.Background(), request)
	require.EqualError(t, err, "upstream failure")
}

func TestOIXCloudLifecycleDelegation(t *testing.T) {
	t.Parallel()

	upstream := &fakeOIXCloudTransport{}
	transport := testOIXCloudTransport(upstream, 1700000000)
	require.Equal(t, "fake", transport.Type())
	require.Equal(t, "fake-tag", transport.Tag())
	require.Equal(t, []string{"dependency"}, transport.Dependencies())
	require.NoError(t, transport.Start(adapter.StartStateStart))
	transport.Reset()
	require.NoError(t, transport.Close())
	require.Equal(t, adapter.StartStateStart, upstream.startStage)
	require.Equal(t, 1, upstream.startCount)
	require.Equal(t, 1, upstream.resetCount)
	require.Equal(t, 1, upstream.closeCount)
}
