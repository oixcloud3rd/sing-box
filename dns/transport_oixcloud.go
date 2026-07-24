package dns

import (
	"context"
	"crypto/ed25519"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"

	mDNS "github.com/miekg/dns"
)

const oixCloudWindowSeconds = int64(300)

var oixCloudEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

type oixCloudTransport struct {
	adapter.DNSTransport
	logger     log.ContextLogger
	privateKey ed25519.PrivateKey
	timeFunc   func() time.Time
}

func newOIXCloudTransport(logger log.ContextLogger, transport adapter.DNSTransport) (adapter.DNSTransport, error) {
	privateKey, err := parseOIXCloudDNSAuthPrivateKey(C.OIXCloudDNSAuthPrivateKey)
	if err != nil {
		return nil, err
	}
	return &oixCloudTransport{
		DNSTransport: transport,
		logger:       logger,
		privateKey:   privateKey,
		timeFunc:     time.Now,
	}, nil
}

func parseOIXCloudDNSAuthPrivateKey(rawKey string) (ed25519.PrivateKey, error) {
	rawKey = strings.TrimSpace(rawKey)
	if rawKey == "" {
		return nil, errors.New("missing oixCloud DNS auth private key: inject OIXCLOUD_DNS_AUTH_PRIVATE_KEY at build time")
	}
	seed, err := base64.StdEncoding.DecodeString(rawKey)
	if err != nil {
		seed, err = base64.RawStdEncoding.DecodeString(rawKey)
		if err != nil {
			return nil, E.Cause(err, "decode oixCloud DNS auth private key")
		}
	}
	if len(seed) != ed25519.SeedSize {
		return nil, E.New("invalid oixCloud DNS auth private key seed length: got ", len(seed), ", want ", ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func (t *oixCloudTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	forward, restore, err := t.prepareMessage(ctx, message)
	if err != nil {
		return nil, err
	}
	response, err := t.DNSTransport.Exchange(ctx, forward)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("empty oixCloud upstream response")
	}
	t.restoreResponse(ctx, response, restore)
	return response, nil
}

func (t *oixCloudTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	forward, restore, err := t.prepareMessage(ctx, message)
	if err != nil {
		callback(nil, err)
		return
	}
	t.DNSTransport.ExchangeAsync(ctx, forward, func(response *mDNS.Msg, err error) {
		if err != nil {
			callback(nil, err)
			return
		}
		if response == nil {
			callback(nil, errors.New("empty oixCloud upstream response"))
			return
		}
		t.restoreResponse(ctx, response, restore)
		callback(response, nil)
	})
}

func (t *oixCloudTransport) prepareMessage(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, map[string]string, error) {
	if message == nil {
		return nil, nil, errors.New("nil oixCloud DNS request")
	}
	forward := message.Copy()
	restore := make(map[string]string, len(forward.Question))
	for questionIndex := range forward.Question {
		original := mDNS.Fqdn(forward.Question[questionIndex].Name)
		signed, err := t.tokenizeHost(original)
		if err != nil {
			return nil, nil, E.Cause(err, "sign DNS question ", original)
		}
		if strings.EqualFold(original, signed) {
			continue
		}
		forward.Question[questionIndex].Name = signed
		restore[strings.ToLower(signed)] = original
		t.logger.DebugContext(ctx, "oixCloud: sign ", original, " -> ", signed)
	}
	return forward, restore, nil
}

func (t *oixCloudTransport) restoreResponse(ctx context.Context, response *mDNS.Msg, names map[string]string) {
	for signed, original := range names {
		t.logger.DebugContext(ctx, "oixCloud: restore ", signed, " -> ", original)
	}
	restoreOIXCloudResponse(response, names)
}

func (t *oixCloudTransport) tokenizeHost(host string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if name == "" {
		return host, nil
	}
	window := t.timeFunc().Unix() / oixCloudWindowSeconds
	signature := ed25519.Sign(t.privateKey, oixCloudAuthMessage(name, window))
	half := ed25519.SignatureSize / 2
	first := strings.ToLower(oixCloudEncoding.EncodeToString(signature[:half]))
	second := strings.ToLower(oixCloudEncoding.EncodeToString(signature[half:]))
	signed := mDNS.Fqdn(first + "." + second + "." + name)
	if _, valid := mDNS.IsDomainName(signed); !valid {
		return "", fmt.Errorf("signed domain exceeds DNS limits: %s", name)
	}
	return signed, nil
}

func oixCloudAuthMessage(name string, window int64) []byte {
	message := make([]byte, 0, len(name)+1+20)
	message = append(message, name...)
	message = append(message, '|')
	return strconv.AppendInt(message, window, 10)
}

func restoreOIXCloudResponse(response *mDNS.Msg, names map[string]string) {
	for questionIndex := range response.Question {
		if original, loaded := names[strings.ToLower(mDNS.Fqdn(response.Question[questionIndex].Name))]; loaded {
			response.Question[questionIndex].Name = original
		}
	}
	restoreOIXCloudRRs(response.Answer, names)
	restoreOIXCloudRRs(response.Ns, names)
	restoreOIXCloudRRs(response.Extra, names)
}

func restoreOIXCloudRRs(records []mDNS.RR, names map[string]string) {
	for _, record := range records {
		if record == nil {
			continue
		}
		header := record.Header()
		if original, loaded := names[strings.ToLower(mDNS.Fqdn(header.Name))]; loaded {
			header.Name = original
		}
		restoreOIXCloudRRTarget(record, names)
	}
}

func restoreOIXCloudRRTarget(record mDNS.RR, names map[string]string) {
	restore := func(name string) string {
		if original, loaded := names[strings.ToLower(mDNS.Fqdn(name))]; loaded {
			return original
		}
		return name
	}
	switch typedRecord := record.(type) {
	case *mDNS.CNAME:
		typedRecord.Target = restore(typedRecord.Target)
	case *mDNS.NS:
		typedRecord.Ns = restore(typedRecord.Ns)
	case *mDNS.PTR:
		typedRecord.Ptr = restore(typedRecord.Ptr)
	case *mDNS.MX:
		typedRecord.Mx = restore(typedRecord.Mx)
	case *mDNS.SRV:
		typedRecord.Target = restore(typedRecord.Target)
	case *mDNS.SOA:
		typedRecord.Ns = restore(typedRecord.Ns)
		typedRecord.Mbox = restore(typedRecord.Mbox)
	case *mDNS.SVCB:
		typedRecord.Target = restore(typedRecord.Target)
	case *mDNS.HTTPS:
		typedRecord.Target = restore(typedRecord.Target)
	}
}
