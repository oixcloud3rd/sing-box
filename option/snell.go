package option

import (
	"reflect"

	"github.com/sagernet/sing-box/schema"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
)

type _SnellInboundOptions struct {
	Version int `json:"version" enum:"5,6"`
	AbstractSnellInboundOptions
	ObfsOptions SnellObfsServerOptions `json:"-"`
	V6Options   SnellV6Options         `json:"-"`
}

type AbstractSnellInboundOptions struct {
	ListenOptions
	PSK      string      `json:"psk"`
	Users    []SnellUser `json:"users,omitempty"`
	Identity bool        `json:"identity,omitempty"`
	InboundTLSOptionsContainer
}

type SnellInboundOptions _SnellInboundOptions

func (o *SnellInboundOptions) UnmarshalJSON(content []byte) error {
	err := json.Unmarshal(content, (*_SnellInboundOptions)(o))
	if err != nil {
		return err
	}
	var versionOptions any
	switch o.Version {
	case 5:
		versionOptions = &o.ObfsOptions
	case 6:
		versionOptions = &o.V6Options
	case 0:
		return E.New("snell: missing version")
	default:
		return E.New("snell: unsupported version: ", o.Version)
	}
	return badjson.UnmarshallExcluded(content, (*_SnellInboundOptions)(o), versionOptions)
}

func (o SnellInboundOptions) MarshalJSON() ([]byte, error) {
	var versionOptions any
	switch o.Version {
	case 5:
		versionOptions = o.ObfsOptions
	case 6:
		versionOptions = o.V6Options
	case 0:
		return nil, E.New("snell: missing version")
	default:
		return nil, E.New("snell: unsupported version: ", o.Version)
	}
	return badjson.MarshallObjects(_SnellInboundOptions(o), versionOptions)
}

func (o SnellInboundOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return schema.DiscriminatedUnion(builder, "version", true, []schema.UnionVariant{
		{Value: 5, StructType: reflect.TypeFor[SnellObfsServerOptions]()},
		{Value: 6, StructType: reflect.TypeFor[SnellV6Options]()},
	}, func(variant *schema.Node) error {
		return builder.FlattenStruct(variant, reflect.TypeFor[AbstractSnellInboundOptions]())
	})
}

type _SnellOutboundOptions struct {
	Version int `json:"version" enum:"4,6"`
	AbstractSnellOutboundOptions
	ObfsOptions SnellObfsClientOptions `json:"-"`
	V6Options   SnellV6Options         `json:"-"`
}

type AbstractSnellOutboundOptions struct {
	DialerOptions
	ServerOptions
	PSK        string                 `json:"psk"`
	UserKey    string                 `json:"userkey,omitempty"`
	Identity   *int                   `json:"identity,omitempty" enum:"1,2"`
	Reuse      bool                   `json:"reuse,omitempty"`
	Preconnect int                    `json:"preconnect,omitempty" enum:"0,1,2,3,4"`
	Network    NetworkList            `json:"network,omitempty"`
	Transport  *SnellTransportOptions `json:"transport,omitempty"`
	OutboundTLSOptionsContainer
}

type SnellTransportOptions struct {
	Type                  string  `json:"type" enum:"http3"`
	HappyEyeballs         bool    `json:"happy_eyeballs,omitempty"`
	QUICCongestionControl string  `json:"quic_congestion_control,omitempty" enum:"reno,cubic,bbr"`
	BBRProfile            *string `json:"bbr_profile,omitempty" enum:"standard,conservative,aggressive"`
}

func (o *SnellTransportOptions) UnmarshalJSON(content []byte) error {
	type plain SnellTransportOptions
	if err := json.UnmarshalDisallowUnknownFields(content, (*plain)(o)); err != nil {
		return err
	}
	return o.Validate()
}

func (o SnellTransportOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return builder.Define("SnellTransport", func() (*schema.Node, error) {
		node := schema.StrictObject()
		if err := builder.FlattenStruct(node, reflect.TypeFor[SnellTransportOptions]()); err != nil {
			return nil, err
		}
		node.Required = []string{"type"}
		return node, nil
	})
}

func (o SnellTransportOptions) Validate() error {
	if o.Type != "http3" {
		return E.New("snell: unknown transport type: ", o.Type)
	}
	switch o.QUICCongestionControl {
	case "", "reno", "cubic", "bbr":
	default:
		return E.New("snell: unknown QUIC congestion control: ", o.QUICCongestionControl)
	}
	if o.BBRProfile != nil {
		if o.QUICCongestionControl != "bbr" {
			return E.New("snell: bbr_profile requires BBR congestion control")
		}
		switch *o.BBRProfile {
		case "standard", "conservative", "aggressive":
		default:
			return E.New("snell: unknown BBR profile: ", *o.BBRProfile)
		}
	}
	return nil
}

type SnellOutboundOptions _SnellOutboundOptions

func (o *SnellOutboundOptions) UnmarshalJSON(content []byte) error {
	err := json.Unmarshal(content, (*_SnellOutboundOptions)(o))
	if err != nil {
		return err
	}
	var versionOptions any
	switch o.Version {
	case 4:
		versionOptions = &o.ObfsOptions
	case 6:
		versionOptions = &o.V6Options
	case 0:
		return E.New("snell: missing version")
	default:
		return E.New("snell: unsupported version: ", o.Version)
	}
	return badjson.UnmarshallExcluded(content, (*_SnellOutboundOptions)(o), versionOptions)
}

func (o SnellOutboundOptions) MarshalJSON() ([]byte, error) {
	var versionOptions any
	switch o.Version {
	case 4:
		versionOptions = o.ObfsOptions
	case 6:
		versionOptions = o.V6Options
	case 0:
		return nil, E.New("snell: missing version")
	default:
		return nil, E.New("snell: unsupported version: ", o.Version)
	}
	return badjson.MarshallObjects(_SnellOutboundOptions(o), versionOptions)
}

func (o SnellOutboundOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return schema.DiscriminatedUnion(builder, "version", true, []schema.UnionVariant{
		{Value: 4, StructType: reflect.TypeFor[SnellObfsClientOptions]()},
		{Value: 6, StructType: reflect.TypeFor[SnellV6Options]()},
	}, func(variant *schema.Node) error {
		return builder.FlattenStruct(variant, reflect.TypeFor[AbstractSnellOutboundOptions]())
	})
}

type SnellObfsServerOptions struct {
	ObfsMode string `json:"obfs_mode,omitempty" enum:"none,http,tls"`
}

type SnellUser struct {
	Name    string `json:"name,omitempty"`
	UserKey string `json:"userkey"`
}

type SnellObfsClientOptions struct {
	ObfsMode string `json:"obfs_mode,omitempty" enum:"none,http,tls"`
	ObfsHost string `json:"obfs_host,omitempty"`
}

type SnellV6Options struct {
	Mode string `json:"mode,omitempty" enum:"default,unshaped,unsafe-raw"`
}
