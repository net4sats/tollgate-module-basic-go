package wireless_gateway_manager

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// IsTollGateSSID checks if an SSID indicates a TollGate router.
// Returns true for "TollGate-*" prefix or stealth checksum match.
func IsTollGateSSID(ssid string) bool {
	if strings.HasPrefix(ssid, "TollGate-") {
		return true
	}
	return VerifyStealthChecksum(ssid)
}

// VerifyStealthChecksum checks if the last 3 hex chars of SSID match
// sha256(SSID_without_last_3_chars). This allows any SSID to encode a
// TollGate marker without using the recognizable "TollGate-" prefix.
//
// Encoding: checksum3 = first 3 hex chars of sha256(SSID[:len-3])
// SSIDs shorter than 4 chars cannot be stealth TollGates.
func VerifyStealthChecksum(ssid string) bool {
	if len(ssid) < 4 {
		return false
	}

	payload := ssid[:len(ssid)-3]
	checksum := ssid[len(ssid)-3:]

	// The checksum part must be valid hex (3 chars = 12 bits).
	for _, c := range checksum {
		if !isHexChar(c) {
			return false
		}
	}

	h := sha256.Sum256([]byte(payload))
	expected := hex.EncodeToString(h[:])[:3]

	return strings.EqualFold(checksum, expected)
}

// GenerateStealthSSID creates a stealth TollGate SSID.
// Format: prefix-randomHex-checksum3
// The checksum is the first 3 hex chars of sha256(prefix + "-" + randomHex).
//
// Example: GenerateStealthSSID("Vodafone", 4) -> "Vodafone-a3f8b2f7e1"
func GenerateStealthSSID(prefix string, randomHexLen int) string {
	if randomHexLen <= 0 {
		randomHexLen = 4
	}

	randomBytes := make([]byte, (randomHexLen+1)/2)
	_, _ = rand.Read(randomBytes)
	randomHex := hex.EncodeToString(randomBytes)[:randomHexLen]

	payload := prefix + "-" + randomHex
	h := sha256.Sum256([]byte(payload))
	checksum := hex.EncodeToString(h[:])[:3]

	return payload + checksum
}

func isHexChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// ValidateStealthSSID verifies that a given SSID was produced by GenerateStealthSSID
// with the given prefix. Useful for testing.
func ValidateStealthSSID(ssid, prefix string) error {
	if !strings.HasPrefix(ssid, prefix+"-") {
		return fmt.Errorf("SSID %q does not start with prefix %q", ssid, prefix)
	}
	if !VerifyStealthChecksum(ssid) {
		return fmt.Errorf("SSID %q has invalid stealth checksum", ssid)
	}
	return nil
}
