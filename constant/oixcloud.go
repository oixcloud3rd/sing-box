package constant

// OIXCloudDNSAuthPrivateKey is an Ed25519 seed for oixCloud DNS authentication
// encoded with base64 and injected at build time. It must not be populated from
// runtime configuration.
var OIXCloudDNSAuthPrivateKey string
