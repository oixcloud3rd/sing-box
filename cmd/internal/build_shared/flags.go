package build_shared

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

const (
	OIXCloudDNSAuthPrivateKeyEnvironment        = "OIXCLOUD_DNS_AUTH_PRIVATE_KEY"
	OIXCloudRequireDNSAuthPrivateKeyEnvironment = "OIXCLOUD_REQUIRE_DNS_AUTH_PRIVATE_KEY"
	oixCloudDNSAuthPrivateKeyLinkerName         = "github.com/sagernet/sing-box/constant.OIXCloudDNSAuthPrivateKey"
)

func LinkerFlags(version string, debug bool) string {
	flags := []string{
		"-X github.com/sagernet/sing-box/constant.Version=" + version,
		"-X runtime.godebugDefault=multipathtcp=0,tlssha1=1,tlsunsafeekm=1",
		"-checklinkname=0",
	}
	oixCloudDNSAuthFlag, err := OIXCloudDNSAuthLinkerFlag(os.Getenv(OIXCloudRequireDNSAuthPrivateKeyEnvironment) == "1")
	if err != nil {
		panic(err)
	}
	if oixCloudDNSAuthFlag != "" {
		flags = append(flags, oixCloudDNSAuthFlag)
	}
	if !debug {
		flags = append(flags, "-s", "-w", "-buildid=")
	}
	return strings.Join(flags, " ")
}

func OIXCloudDNSAuthLinkerFlag(required bool) (string, error) {
	privateKey := strings.TrimSpace(os.Getenv(OIXCloudDNSAuthPrivateKeyEnvironment))
	if privateKey == "" {
		if required {
			return "", fmt.Errorf("missing %s", OIXCloudDNSAuthPrivateKeyEnvironment)
		}
		return "", nil
	}
	seed, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		seed, err = base64.RawStdEncoding.DecodeString(privateKey)
		if err != nil {
			return "", fmt.Errorf("decode %s: %w", OIXCloudDNSAuthPrivateKeyEnvironment, err)
		}
	}
	if len(seed) != 32 {
		return "", fmt.Errorf("invalid %s seed length: got %d, want 32", OIXCloudDNSAuthPrivateKeyEnvironment, len(seed))
	}
	return "-X " + oixCloudDNSAuthPrivateKeyLinkerName + "=" + privateKey, nil
}
