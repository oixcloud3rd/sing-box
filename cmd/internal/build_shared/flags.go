package build_shared

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

const (
	OIXCloudPrivateKeyEnvironment = "OIXCLOUD_PRIVATE_KEY"
	OIXCloudRequireKeyEnvironment = "OIXCLOUD_REQUIRE_PRIVATE_KEY"
	oixCloudPrivateKeyLinkerName  = "github.com/sagernet/sing-box/constant.OIXCloudPrivateKey"
)

func LinkerFlags(version string, debug bool) string {
	flags := []string{
		"-X github.com/sagernet/sing-box/constant.Version=" + version,
		"-X runtime.godebugDefault=multipathtcp=0,tlssha1=1,tlsunsafeekm=1",
		"-checklinkname=0",
	}
	oixCloudFlag, err := OIXCloudLinkerFlag(os.Getenv(OIXCloudRequireKeyEnvironment) == "1")
	if err != nil {
		panic(err)
	}
	if oixCloudFlag != "" {
		flags = append(flags, oixCloudFlag)
	}
	if !debug {
		flags = append(flags, "-s", "-w", "-buildid=")
	}
	return strings.Join(flags, " ")
}

func OIXCloudLinkerFlag(required bool) (string, error) {
	privateKey := strings.TrimSpace(os.Getenv(OIXCloudPrivateKeyEnvironment))
	if privateKey == "" {
		if required {
			return "", fmt.Errorf("missing %s", OIXCloudPrivateKeyEnvironment)
		}
		return "", nil
	}
	seed, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		seed, err = base64.RawStdEncoding.DecodeString(privateKey)
		if err != nil {
			return "", fmt.Errorf("decode %s: %w", OIXCloudPrivateKeyEnvironment, err)
		}
	}
	if len(seed) != 32 {
		return "", fmt.Errorf("invalid %s seed length: got %d, want 32", OIXCloudPrivateKeyEnvironment, len(seed))
	}
	return "-X " + oixCloudPrivateKeyLinkerName + "=" + privateKey, nil
}
