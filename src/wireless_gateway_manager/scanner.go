// Package wireless_gateway_manager implements the Scanner for Wi-Fi network scanning.
package wireless_gateway_manager

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

func getInterfaceName() (string, error) {
	cmd := exec.Command("iw", "dev")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(bytes.NewReader(stdout.Bytes()))
	var currentInterface string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Interface") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				currentInterface = parts[1]
			}
		} else if strings.HasPrefix(line, "type") && strings.Contains(line, "managed") {
			if currentInterface != "" {
				return currentInterface, nil
			}
		}
	}
	return "", errors.New("no managed Wi-Fi interface found")
}

// Ensure Scanner implements ScannerInterface
var _ ScannerInterface = (*Scanner)(nil)

func (s *Scanner) ScanAllRadios() ([]NetworkInfo, error) {
	radios, err := s.GetRadios()
	if err != nil {
		return nil, err
	}

	if len(radios) == 0 {
		return nil, errors.New("no radios found")
	}

	type scanResult struct {
		networks []NetworkInfo
		err      error
	}

	results := make(chan scanResult, len(radios))
	for _, radio := range radios {
		go func(r string) {
			networks, err := s.scanRadio(r)
			results <- scanResult{networks: networks, err: err}
		}(radio)
	}

	var allNetworks []NetworkInfo
	for i := 0; i < len(radios); i++ {
		result := <-results
		if result.err != nil {
			logger.WithError(result.err).Warn("Radio scan failed")
			continue
		}
		allNetworks = append(allNetworks, result.networks...)
	}

	sort.Slice(allNetworks, func(i, j int) bool {
		return allNetworks[i].Signal > allNetworks[j].Signal
	})

	return allNetworks, nil
}

func (s *Scanner) scanRadio(radio string) ([]NetworkInfo, error) {
	var lastErr error
	for retry := 0; retry < 3; retry++ {
		cmd := exec.Command("iwinfo", radio, "scan")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			lastErr = err
			time.Sleep(2 * time.Second)
			continue
		}

		output := stdout.String()
		if output == "" || strings.Contains(strings.ToLower(output), "no scan result") {
			lastErr = errors.New("empty scan result")
			time.Sleep(2 * time.Second)
			continue
		}

		return s.ParseIwinfoOutput(stdout.Bytes(), radio), nil
	}

	return nil, lastErr
}

func (s *Scanner) ParseIwinfoOutput(output []byte, radio string) []NetworkInfo {
	scanner := bufio.NewScanner(bytes.NewReader(output))
	var networks []NetworkInfo

	var current *struct {
		bssid    string
		ssid     string
		signal   int
		encrypt  string
		channel  string
		hasSignal bool
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "Address:") {
			if current != nil && current.ssid != "" && current.hasSignal {
				networks = append(networks, NetworkInfo{
					BSSID:      current.bssid,
					SSID:       current.ssid,
					Signal:     current.signal,
					Encryption: current.encrypt,
					Radio:      radio,
				})
			}
			fields := strings.Fields(line)
			current = &struct {
				bssid    string
				ssid     string
				signal   int
				encrypt  string
				channel  string
				hasSignal bool
			}{}
			if len(fields) > 0 {
				current.bssid = fields[len(fields)-1]
			}
			continue
		}

		if current == nil {
			continue
		}

		if strings.Contains(line, "ESSID:") {
			start := strings.Index(line, `"`)
			end := strings.LastIndex(line, `"`)
			if start >= 0 && end > start {
				current.ssid = line[start+1 : end]
			}
			if current.ssid == "" {
				current.ssid = "(hidden)"
			}
			continue
		}

		if strings.Contains(line, "Signal:") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "Signal:" && i+1 < len(fields) {
					sig, err := strconv.Atoi(strings.TrimSuffix(fields[i+1], "dBm"))
					if err == nil {
						current.signal = sig
						current.hasSignal = true
					}
					break
				}
			}
			continue
		}

		if strings.Contains(line, "Encryption:") {
			idx := strings.Index(line, "Encryption:")
			if idx >= 0 {
				current.encrypt = strings.TrimSpace(line[idx+len("Encryption:"):])
			}
			continue
		}

		if strings.Contains(line, "Channel:") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "Channel:" && i+1 < len(fields) {
					current.channel = fields[i+1]
					break
				}
			}
			continue
		}
	}

	if current != nil && current.ssid != "" && current.hasSignal && current.ssid != "(hidden)" {
		networks = append(networks, NetworkInfo{
			BSSID:      current.bssid,
			SSID:       current.ssid,
			Signal:     current.signal,
			Encryption: current.encrypt,
			Radio:      radio,
		})
	}

	return networks
}

func (s *Scanner) GetRadios() ([]string, error) {
	data, err := os.ReadFile("/etc/config/wireless")
	if err != nil {
		return nil, fmt.Errorf("failed to read wireless config: %w", err)
	}

	var radios []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "config wifi-device") {
			start := strings.Index(line, "'")
			end := strings.LastIndex(line, "'")
			if start >= 0 && end > start {
				radios = append(radios, line[start+1:end])
			}
		}
	}
	return radios, nil
}

func (s *Scanner) DetectEncryption(encryptionStr string) string {
	e := strings.ToLower(encryptionStr)

	if strings.Contains(e, "none") || strings.Contains(e, "open") || strings.HasPrefix(e, "wep") {
		return "none"
	}

	if strings.Contains(e, "sae") && strings.Contains(e, "mixed") {
		return "sae-mixed"
	}
	if strings.Contains(e, "sae") {
		return "sae"
	}
	if strings.Contains(e, "wpa2") && strings.Contains(e, "psk") {
		return "psk2"
	}
	if strings.Contains(e, "wpa") && strings.Contains(e, "psk") {
		return "psk"
	}
	if strings.Contains(e, "eap") {
		return "wpa2-eap"
	}

	return "psk2"
}

func (s *Scanner) FindBestRadioForSSID(ssid string, networks []NetworkInfo) (string, error) {
	for _, net := range networks {
		if net.SSID == ssid {
			return net.Radio, nil
		}
	}
	return "", fmt.Errorf("SSID '%s' not found in scan results", ssid)
}

func FormatScanResults(networks []NetworkInfo) string {
	if len(networks) == 0 {
		return "No networks found"
	}

	var result string
	result = fmt.Sprintf("%-30s %-15s %-20s %s\n", "SSID", "Signal", "Encryption", "Radio")
	result += fmt.Sprintf("%s\n", "----------------------------------------------------------------------")
	for _, net := range networks {
		result += fmt.Sprintf("%-30s %-15s %-20s %s\n", net.SSID, fmt.Sprintf("%d dBm", net.Signal), net.Encryption, net.Radio)
	}
	result += fmt.Sprintf("\n%d network(s) found.", len(networks))
	return result
}

func phyForRadio(radio string) (string, error) {
	idx := strings.TrimPrefix(radio, "radio")
	if idx == radio || idx == "" {
		return "", fmt.Errorf("invalid radio name %q: expected radio<N>", radio)
	}
	return idx, nil
}

func (s *Scanner) ScanVendorIEs(radio string) (map[string]*TollGateAdvertisement, error) {
	idx, err := phyForRadio(radio)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve phy for radio %q: %w", radio, err)
	}

	// iw scan requires a dev interface name, not phy<N>.
	// Use "phy<idx>-ap0" which is the standard OpenWrt naming for the first AP on each radio.
	devName := fmt.Sprintf("phy%s-ap0", idx)

	cmd := exec.Command("iw", "dev", devName, "scan", "-u")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("iw dev %s scan failed: %w", devName, err)
	}

	return s.ParseIwScanForVendorIEs(stdout.Bytes()), nil
}

func (s *Scanner) ParseIwScanForVendorIEs(output []byte) map[string]*TollGateAdvertisement {
	results := make(map[string]*TollGateAdvertisement)

	var currentBSSID string
	var vendorIEBytes []byte

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "BSS ") {
			if currentBSSID != "" && len(vendorIEBytes) > 0 {
				if adv := ParseTollGateVendorIE(vendorIEBytes); adv != nil {
					results[currentBSSID] = adv
				}
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				currentBSSID = strings.Split(fields[1], "(")[0]
				vendorIEBytes = nil
			}
			continue
		}

		if strings.Contains(line, "Vendor specific:") && strings.Contains(line, "21:21:21") {
			oui := extractVendorIEData(line)
			if oui != nil {
				vendorIEBytes = oui
			}
		}
	}

	if currentBSSID != "" && len(vendorIEBytes) > 0 {
		if adv := ParseTollGateVendorIE(vendorIEBytes); adv != nil {
			results[currentBSSID] = adv
		}
	}

	return results
}

func extractVendorIEData(line string) []byte {
	// Real iw output format: "Vendor specific: OUI 21:21:21, data: 01 00 01 ..."
	// The hex bytes after "data:" are the body after OUI bytes (version + flags + optional TLVs).
	// Build a synthetic IE: DD <len> 21 21 21 <data bytes>

	dataIdx := strings.Index(line, ", data:")
	if dataIdx < 0 {
		return nil
	}

	hexPart := line[dataIdx+len(", data:"):]
	hexFields := strings.Fields(hexPart)
	var dataBytes []byte
	for _, h := range hexFields {
		b, err := strconv.ParseUint(h, 16, 8)
		if err != nil {
			break
		}
		dataBytes = append(dataBytes, byte(b))
	}

	if len(dataBytes) == 0 {
		return nil
	}

	body := []byte{0x21, 0x21, 0x21}
	body = append(body, dataBytes...)

	ie := []byte{0xDD, uint8(len(body))}
	ie = append(ie, body...)

	return ie
}

func EnrichNetworksWithVendorIEs(networks []NetworkInfo, ieMap map[string]*TollGateAdvertisement) []NetworkInfo {
	for i := range networks {
		adv, ok := ieMap[networks[i].BSSID]
		if ok {
			networks[i].IsTollGate = true
			networks[i].TollGateAdv = adv
		}
	}
	return networks
}

func init() {
	logger.WithField("module", "wireless_gateway_manager").Info("Wireless gateway manager module loaded")
}

