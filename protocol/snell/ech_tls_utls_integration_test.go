//go:build with_utls

package snell

import "testing"

func TestSnellECHTLSRawUTLS(t *testing.T) {
	testSnellECHTLSRaw(t, "snell-ech/1", true)
}

func TestSnellECHTLSRawUTLSEmptyALPN(t *testing.T) {
	testSnellECHTLSRaw(t, "", true)
}
