package wireless_gateway_manager

import (
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	tollgateOUI         = "212121"
	tollgateElemType    = "01"
	tollgateElemTypeByte byte = 0x01

	flagIsReseller  = 0x01
	flagHasInternet = 0x02
	flagOpenNetwork = 0x04

	tlvTypeMintURL = 0x01
	tlvTypePubkey  = 0x02
)

// EncodeTollGateVendorIE builds a complete 802.11 vendor-specific IE hex string.
// Wire format: DD <len> <OUI 3B> <type 1B> <version 1B> <flags 1B>.
func EncodeTollGateVendorIE(adv TollGateAdvertisement) (string, error) {
	var flags uint8
	if adv.IsReseller {
		flags |= flagIsReseller
	}
	if adv.HasInternet {
		flags |= flagHasInternet
	}
	if adv.OpenNetwork {
		flags |= flagOpenNetwork
	}

	oui, err := hex.DecodeString(tollgateOUI)
	if err != nil {
		return "", fmt.Errorf("invalid OUI hex: %w", err)
	}

	elemType, _ := hex.DecodeString(tollgateElemType)
	body := append(oui, elemType...)
	body = append(body, adv.Version, flags)

	if adv.MintURL != "" {
		mintBytes := []byte(adv.MintURL)
		if len(mintBytes) > 255 {
			return "", fmt.Errorf("mint_url too long: %d bytes (max 255)", len(mintBytes))
		}
		body = append(body, tlvTypeMintURL, uint8(len(mintBytes)))
		body = append(body, mintBytes...)
	}

	if len(adv.Pubkey) > 0 {
		if len(adv.Pubkey) > 255 {
			return "", fmt.Errorf("pubkey too long: %d bytes (max 255)", len(adv.Pubkey))
		}
		body = append(body, tlvTypePubkey, uint8(len(adv.Pubkey)))
		body = append(body, adv.Pubkey...)
	}

	ie := append([]byte{0xDD, uint8(len(body))}, body...)

	return hex.EncodeToString(ie), nil
}

// ParseTollGateVendorIE extracts a TollGateAdvertisement from raw vendor IE bytes.
// Expects the full IE (element ID + length + body), returns nil if not a TollGate IE.
func ParseTollGateVendorIE(raw []byte) *TollGateAdvertisement {
	if len(raw) < 8 {
		return nil
	}
	if raw[0] != 0xDD {
		return nil
	}

	bodyLen := int(raw[1])
	if len(raw) < 2+bodyLen {
		return nil
	}
	body := raw[2:]

	oui := fmt.Sprintf("%02x%02x%02x", body[0], body[1], body[2])
	if oui != tollgateOUI {
		return nil
	}
	if body[3] != tollgateElemTypeByte {
		return nil
	}

	adv := &TollGateAdvertisement{
		Version: body[4],
	}

	if len(body) > 5 {
		flags := body[5]
		adv.IsReseller = flags&flagIsReseller != 0
		adv.HasInternet = flags&flagHasInternet != 0
		adv.OpenNetwork = flags&flagOpenNetwork != 0
	}

	tlvOffset := 6
	for tlvOffset+2 <= len(body) {
		tlvType := body[tlvOffset]
		tlvLen := int(body[tlvOffset+1])
		if tlvOffset+2+tlvLen > len(body) {
			break
		}
		tlvValue := body[tlvOffset+2 : tlvOffset+2+tlvLen]

		switch tlvType {
		case tlvTypeMintURL:
			adv.MintURL = string(tlvValue)
		case tlvTypePubkey:
			adv.Pubkey = make([]byte, len(tlvValue))
			copy(adv.Pubkey, tlvValue)
		}

		tlvOffset += 2 + tlvLen
	}

	return adv
}

// ParseVendorIEsFromScanData walks raw 802.11 IE bytes and returns all
// TollGate vendor IEs found.
func ParseVendorIEsFromScanData(raw []byte) []*TollGateAdvertisement {
	var results []*TollGateAdvertisement

	offset := 0
	for offset+1 < len(raw) {
		elemID := raw[offset]
		length := int(raw[offset+1])

		if offset+2+length > len(raw) {
			break
		}

		if elemID == 0xDD && length >= 4 {
			ieBytes := raw[offset : offset+2+length]
			if adv := ParseTollGateVendorIE(ieBytes); adv != nil {
				results = append(results, adv)
			}
		}

		offset += 2 + length
	}

	return results
}

func (v *VendorElementProcessor) ExtractAndScore(ni NetworkInfo) (map[string]interface{}, int, error) {
	vendorElements := make(map[string]interface{})
	score := v.calculateScore(ni, vendorElements)
	return vendorElements, score, nil
}

func (v *VendorElementProcessor) calculateScore(ni NetworkInfo, vendorElements map[string]interface{}) int {
	score := ni.Signal

	if strings.HasPrefix(ni.SSID, "TollGate-") {
		score += 100
	}

	if ni.IsTollGate {
		score += 200
	}

	return score
}

func (v *VendorElementProcessor) SetLocalAPVendorElements(elements map[string]string) error {
	logger.WithFields(logrus.Fields{
		"elements": elements,
	}).Debug("SetLocalAPVendorElements: setting vendor elements on local AP")

	var hexIEs []string
	for _, h := range elements {
		hexIEs = append(hexIEs, h)
	}
	combinedHex := strings.Join(hexIEs, "")

	// Try UCI first (works on all drivers including mt76).
	if err := v.SetVendorElementsViaUCI(combinedHex); err != nil {
		logger.WithError(err).Warn("SetLocalAPVendorElements: UCI method failed, trying ubus fallback")
	} else {
		return nil
	}

	// Fallback: ubus runtime method.
	return v.setVendorElementsViaUbus(elements)
}

// SetVendorElementsViaUCI writes vendor_elements to /etc/config/wireless
// for all AP iface sections and triggers wifi reload. This works on all
// drivers because hostapd reads vendor_elements at startup.
func (v *VendorElementProcessor) SetVendorElementsViaUCI(hexIE string) error {
	output, err := v.connector.ExecuteUCI("show", "wireless")
	if err != nil {
		return fmt.Errorf("failed to read wireless config: %w", err)
	}

	var apIfaces []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "=wifi-iface") {
			continue
		}
		parts := strings.SplitN(line, ".", 2)
		if len(parts) < 2 {
			continue
		}
		sectionPart := parts[1]
		eqIdx := strings.Index(sectionPart, "=")
		if eqIdx < 0 {
			continue
		}
		ifaceName := sectionPart[:eqIdx]

		modeOut, err := v.connector.ExecuteUCI("get", "wireless."+ifaceName+".mode")
		if err != nil || strings.TrimSpace(modeOut) != "ap" {
			continue
		}

		apIfaces = append(apIfaces, ifaceName)
	}

	if len(apIfaces) == 0 {
		logger.Warn("SetVendorElementsViaUCI: no AP interfaces found")
		return fmt.Errorf("no AP wifi-iface sections found")
	}

	for _, iface := range apIfaces {
		if _, err := v.connector.ExecuteUCI("set", "wireless."+iface+".vendor_elements="+hexIE); err != nil {
			logger.WithFields(logrus.Fields{
				"iface": iface,
				"error": err,
			}).Warn("SetVendorElementsViaUCI: failed to set vendor_elements")
			continue
		}
		logger.WithField("iface", iface).Debug("SetVendorElementsViaUCI: set vendor_elements")
	}

	if _, err := v.connector.ExecuteUCI("commit", "wireless"); err != nil {
		return fmt.Errorf("failed to commit wireless config: %w", err)
	}

	cmd := exec.Command("wifi", "reload")
	if err := cmd.Run(); err != nil {
		logger.WithError(err).Warn("SetVendorElementsViaUCI: wifi reload failed, change will apply on next reboot")
	} else {
		logger.Info("SetVendorElementsViaUCI: vendor elements set, wifi reloaded")
	}

	return nil
}

func (v *VendorElementProcessor) setVendorElementsViaUbus(elements map[string]string) error {
	output, err := v.connector.ExecuteUbus("list")
	if err != nil {
		logger.WithError(err).Warn("setVendorElementsViaUbus: ubus list failed, hostapd may not be running")
		return nil
	}

	var hostapdIfaces []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "hostapd.") {
			hostapdIfaces = append(hostapdIfaces, line)
		}
	}

	if len(hostapdIfaces) == 0 {
		logger.Warn("setVendorElementsViaUbus: no hostapd interfaces found")
		return nil
	}

	var hexIEs []string
	for _, h := range elements {
		hexIEs = append(hexIEs, h)
	}
	combinedHex := strings.Join(hexIEs, "")

	for _, iface := range hostapdIfaces {
		jsonPayload := fmt.Sprintf(`{"vendor_elements":"%s"}`, combinedHex)
		_, err := v.connector.ExecuteUbus("call", iface, "set_vendor_elements", jsonPayload)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"interface": iface,
				"error":     err,
			}).Warn("setVendorElementsViaUbus: failed to set vendor elements on interface")
			continue
		}
		logger.WithField("interface", iface).Info("setVendorElementsViaUbus: vendor elements set")
	}

	return nil
}

func (v *VendorElementProcessor) GetLocalAPVendorElements() (map[string]string, error) {
	return make(map[string]string), nil
}

func NewVendorElementProcessor(connector *Connector) *VendorElementProcessor {
	return &VendorElementProcessor{connector: connector}
}

func EmitTollGateVendorIE(processor *VendorElementProcessor, adv TollGateAdvertisement) error {
	ieHex, err := EncodeTollGateVendorIE(adv)
	if err != nil {
		return fmt.Errorf("failed to encode vendor IE: %w", err)
	}

	elements := map[string]string{"tollgate": ieHex}
	return processor.SetLocalAPVendorElements(elements)
}
