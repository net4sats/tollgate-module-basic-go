package wireless_gateway_manager

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestIsTollGateSSID_PrefixMatch(t *testing.T) {
	tests := []struct {
		ssid string
		want bool
	}{
		{"TollGate-ABC", true},
		{"TollGate-", true},
		{"TollGate-1234", true},
		{"tollgate-lower", false},
		{"MyTollGate-ABC", false},
		{"Something-Else", false},
	}
	for _, tt := range tests {
		got := IsTollGateSSID(tt.ssid)
		if got != tt.want {
			t.Errorf("IsTollGateSSID(%q) = %v, want %v", tt.ssid, got, tt.want)
		}
	}
}

func TestVerifyStealthChecksum_TooShort(t *testing.T) {
	short := []string{"", "a", "ab", "abc"}
	for _, s := range short {
		if VerifyStealthChecksum(s) {
			t.Errorf("VerifyStealthChecksum(%q) = true, want false (too short)", s)
		}
	}
}

func TestVerifyStealthChecksum_ManualValid(t *testing.T) {
	// Manually construct a valid stealth SSID.
	// payload = "ABCD", expected checksum = first 3 hex of sha256("ABCD")
	payload := "ABCD"
	h := sha256.Sum256([]byte(payload))
	checksum := hex.EncodeToString(h[:])[:3]
	ssid := payload + checksum

	if !VerifyStealthChecksum(ssid) {
		t.Errorf("VerifyStealthChecksum(%q) = false, want true", ssid)
	}
	if !IsTollGateSSID(ssid) {
		t.Errorf("IsTollGateSSID(%q) = false, want true", ssid)
	}
}

func TestVerifyStealthChecksum_ManualInvalid(t *testing.T) {
	ssid := "ABCD000" // almost certainly wrong checksum
	// Compute actual checksum to make sure they differ
	h := sha256.Sum256([]byte("ABCD"))
	actual := hex.EncodeToString(h[:])[:3]
	if strings.EqualFold("000", actual) {
		t.Skip("checksum happened to be 000, skipping")
	}
	if VerifyStealthChecksum(ssid) {
		t.Errorf("VerifyStealthChecksum(%q) = true, want false", ssid)
	}
}

func TestVerifyStealthChecksum_NonHexChecksum(t *testing.T) {
	ssid := "ABCDEFG" // G is not hex
	if VerifyStealthChecksum(ssid) {
		t.Errorf("VerifyStealthChecksum(%q) = true, want false (non-hex checksum)", ssid)
	}
}

func TestVerifyStealthChecksum_CaseInsensitive(t *testing.T) {
	payload := "test"
	h := sha256.Sum256([]byte(payload))
	checksum := strings.ToUpper(hex.EncodeToString(h[:])[:3])

	lowerSSID := payload + strings.ToLower(checksum)
	upperSSID := payload + strings.ToUpper(checksum)
	mixedSSID := payload + checksum

	if !VerifyStealthChecksum(lowerSSID) {
		t.Errorf("VerifyStealthChecksum(%q) = false, want true (lower)", lowerSSID)
	}
	if !VerifyStealthChecksum(upperSSID) {
		t.Errorf("VerifyStealthChecksum(%q) = false, want true (upper)", upperSSID)
	}
	if !VerifyStealthChecksum(mixedSSID) {
		t.Errorf("VerifyStealthChecksum(%q) = false, want true (mixed)", mixedSSID)
	}
}

func TestGenerateStealthSSID_RoundTrip(t *testing.T) {
	for i := 0; i < 100; i++ {
		ssid := GenerateStealthSSID("TestPrefix", 4)
		if !VerifyStealthChecksum(ssid) {
			t.Errorf("GenerateStealthSSID produced invalid SSID: %q", ssid)
		}
		if !IsTollGateSSID(ssid) {
			t.Errorf("IsTollGateSSID(%q) = false, want true", ssid)
		}
		if !strings.HasPrefix(ssid, "TestPrefix-") {
			t.Errorf("SSID %q doesn't have expected prefix", ssid)
		}
	}
}

func TestGenerateStealthSSID_VariousRandomLengths(t *testing.T) {
	lengths := []int{1, 2, 4, 8, 16}
	for _, l := range lengths {
		ssid := GenerateStealthSSID("P", l)
		if !VerifyStealthChecksum(ssid) {
			t.Errorf("randomHexLen=%d produced invalid SSID: %q", l, ssid)
		}
		// payload is "P-" + randomHex, last 3 chars are checksum
		expectedPayloadLen := 2 + l
		if len(ssid) != expectedPayloadLen+3 {
			t.Errorf("SSID length = %d, want %d (prefix=2, random=%d, checksum=3)", len(ssid), expectedPayloadLen+3, l)
		}
	}
}

func TestGenerateStealthSSID_DefaultRandomLen(t *testing.T) {
	ssid := GenerateStealthSSID("X", 0)
	if !VerifyStealthChecksum(ssid) {
		t.Errorf("GenerateStealthSSID with randomHexLen=0 produced invalid SSID: %q", ssid)
	}
	// default is 4, so payload is "X-" (2) + 4 random hex = 6 chars, + 3 checksum = 9
	if len(ssid) != 9 {
		t.Errorf("SSID length = %d, want 9", len(ssid))
	}
}

func TestGenerateStealthSSID_DifferentPrefixes(t *testing.T) {
	prefixes := []string{"Vodafone", "CafeWiFi", "FreeNet", "A"}
	for _, prefix := range prefixes {
		ssid := GenerateStealthSSID(prefix, 4)
		if !VerifyStealthChecksum(ssid) {
			t.Errorf("prefix=%q produced invalid SSID: %q", prefix, ssid)
		}
		if !strings.HasPrefix(ssid, prefix+"-") {
			t.Errorf("SSID %q doesn't start with %q-", ssid, prefix)
		}
	}
}

func TestGenerateStealthSSID_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		ssid := GenerateStealthSSID("Uniq", 8)
		if seen[ssid] {
			t.Errorf("duplicate SSID generated: %q", ssid)
		}
		seen[ssid] = true
	}
}

func TestIsTollGateSSID_PrefixTakesPrecedenceOverChecksum(t *testing.T) {
	// "TollGate-" prefixed SSIDs should always match even without valid checksum.
	if !IsTollGateSSID("TollGate-anything") {
		t.Error("TollGate- prefix should always match")
	}
}

func TestValidateStealthSSID(t *testing.T) {
	ssid := GenerateStealthSSID("Test", 4)
	if err := ValidateStealthSSID(ssid, "Test"); err != nil {
		t.Errorf("ValidateStealthSSID(%q, 'Test') = %v", ssid, err)
	}
	if err := ValidateStealthSSID(ssid, "Wrong"); err == nil {
		t.Errorf("ValidateStealthSSID(%q, 'Wrong') should fail", ssid)
	}
	if err := ValidateStealthSSID("invalid-nochecksum", "invalid"); err == nil {
		t.Error("ValidateStealthSSID with invalid checksum should fail")
	}
}
