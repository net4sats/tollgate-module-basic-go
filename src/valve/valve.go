package valve

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Module-level logger with pre-configured module field
var logger = logrus.WithField("module", "valve")

// AuthDelay controls a delay before ndsctl auth, giving the captive portal
// time to load a redirect page before Android detects connectivity and
// closes the WebView. Set to 0 (default) for immediate auth.
var AuthDelay time.Duration

// openGates keeps track of MAC addresses that have been authorized.
// pendingUntil stores target deauth timestamps for MACs awaiting delayed auth,
// so extensions during the delay window are preserved (fixes concurrent payment bug).
var (
	openGates    = make(map[string]*time.Timer)
	gatesMutex   = &sync.Mutex{}
	pendingUntil = make(map[string]int64)
)

// ndsctlMutex ensures only one ndsctl command runs at a time
var ndsctlMutex = &sync.Mutex{}

// authorizeMAC authorizes a MAC address using ndsctl
func authorizeMAC(macAddress string) error {
	ndsctlMutex.Lock()
	cmd := exec.Command("ndsctl", "auth", macAddress)
	output, err := cmd.Output()
	ndsctlMutex.Unlock()

	if err != nil {
		logger.WithFields(logrus.Fields{
			"mac_address": macAddress,
			"error":       err,
		}).Error("Error authorizing MAC address")
		return err
	}

	logger.WithFields(logrus.Fields{
		"mac_address": macAddress,
		"output":      string(output),
	}).Info("Authorization successful for MAC")
	return nil
}

// deauthorizeMAC deauthorizes a MAC address using ndsctl
func deauthorizeMAC(macAddress string) error {
	ndsctlMutex.Lock()
	cmd := exec.Command("ndsctl", "deauth", macAddress)
	output, err := cmd.Output()
	ndsctlMutex.Unlock()

	if err != nil {
		logger.WithFields(logrus.Fields{
			"mac_address": macAddress,
			"error":       err,
		}).Error("Error deauthorizing MAC address")
		return err
	}

	logger.WithFields(logrus.Fields{
		"mac_address": macAddress,
		"output":      string(output),
	}).Debug("Deauthorization successful for MAC")
	return nil
}

// OpenGateUntil opens the gate (if not opened yet) and sets a timer until the timestamp.
// If there is already a timer running, it will extend the timer.
// When AuthDelay > 0, auth is deferred to a goroutine that reads the latest
// untilTimestamp from pendingUntil — extensions during the delay are preserved.
func OpenGateUntil(macAddress string, untilTimestamp int64) error {
	now := time.Now().Unix()

	durationSeconds := untilTimestamp - now

	if durationSeconds <= 0 {
		return fmt.Errorf("timestamp %d is in the past (current time: %d)", untilTimestamp, now)
	}

	logger.WithFields(logrus.Fields{
		"mac_address":      macAddress,
		"until_timestamp":  untilTimestamp,
		"duration_seconds": durationSeconds,
	}).Info("Opening gate until timestamp")

	gatesMutex.Lock()
	defer gatesMutex.Unlock()

	existingTimer, exists := openGates[macAddress]

	if !exists {
		if AuthDelay > 0 {
			pendingUntil[macAddress] = untilTimestamp
			openGates[macAddress] = nil
			go delayedAuth(macAddress)
			logger.WithFields(logrus.Fields{
				"mac_address": macAddress,
				"delay":       AuthDelay,
			}).Info("Scheduled delayed auth for redirect")
			return nil
		}

		err := authorizeMAC(macAddress)
		if err != nil {
			return fmt.Errorf("error authorizing MAC: %w", err)
		}
		logger.WithFields(logrus.Fields{
			"mac_address": macAddress,
		}).Debug("New authorization for MAC")
	} else if _, pending := pendingUntil[macAddress]; pending {
		pendingUntil[macAddress] = untilTimestamp
		logger.WithFields(logrus.Fields{
			"mac_address":     macAddress,
			"until_timestamp": untilTimestamp,
		}).Info("Extended pending delayed auth")
		return nil
	} else {
		if existingTimer != nil {
			existingTimer.Stop()
		}
		logger.WithFields(logrus.Fields{
			"mac_address": macAddress,
		}).Debug("Extending access for already authorized MAC")
	}

	duration := time.Duration(durationSeconds) * time.Second
	timer := time.AfterFunc(duration, func() {
		err := deauthorizeMAC(macAddress)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"mac_address": macAddress,
				"error":       err,
			}).Error("Error deauthorizing MAC after timeout")
		} else {
			logger.WithFields(logrus.Fields{
				"mac_address": macAddress,
			}).Debug("Successfully deauthorized MAC after timeout")
		}

		gatesMutex.Lock()
		delete(openGates, macAddress)
		gatesMutex.Unlock()
	})

	openGates[macAddress] = timer

	return nil
}

// OpenGate authorizes a MAC address without a timer.
// It's used for data-based sessions that are closed by a tracker.
// It captures the current data usage as a baseline for tracking.
func OpenGate(macAddress string) error {
	gatesMutex.Lock()
	defer gatesMutex.Unlock()

	_, exists := openGates[macAddress]
	if existingTimer, ok := openGates[macAddress]; ok {
		if existingTimer != nil {
			existingTimer.Stop()
		}
		logger.WithField("mac_address", macAddress).Info("Replacing existing timed gate with indefinite data-based gate.")
	}

	if AuthDelay > 0 {
		if !exists {
			go delayedAuthIndefinite(macAddress)
			logger.WithFields(logrus.Fields{
				"mac_address": macAddress,
				"delay":       AuthDelay,
			}).Info("Scheduled delayed auth for redirect")
		}
	} else {
		err := authorizeMAC(macAddress)
		if err != nil {
			return err
		}

		err = SetDataBaseline(macAddress)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"mac_address": macAddress,
				"error":       err,
			}).Warn("Failed to set data baseline, continuing anyway")
		}
	}

	// Store a nil timer to indicate an indefinite gate
	openGates[macAddress] = nil
	return nil
}

// CloseGate deauthorizes a MAC address and removes it from the active gates.
func CloseGate(macAddress string) error {
	gatesMutex.Lock()
	defer gatesMutex.Unlock()

	if _, exists := openGates[macAddress]; !exists {
		logger.WithField("mac_address", macAddress).Warn("Attempted to close a gate that was not open.")
		// still attempt to deauth, in case the state is out of sync
	}

	err := deauthorizeMAC(macAddress)
	if err != nil {
		return err
	}

	// Clean up from active gates map and data baseline
	delete(openGates, macAddress)
	ClearDataBaseline(macAddress)
	return nil
}

// ClientStats represents the statistics for a single client from ndsctl
type ClientStats struct {
	ID           int     `json:"id"`
	IP           string  `json:"ip"`
	MAC          string  `json:"mac"`
	Added        int64   `json:"added"`
	Active       int64   `json:"active"`
	Duration     int64   `json:"duration"`
	Token        string  `json:"token"`
	State        string  `json:"state"`
	Downloaded   uint64  `json:"downloaded"` // in kilobytes
	AvgDownSpeed float64 `json:"avg_down_speed"`
	Uploaded     uint64  `json:"uploaded"` // in kilobytes
	AvgUpSpeed   float64 `json:"avg_up_speed"`
}

// GetClientStats retrieves the current data usage statistics for a MAC address from ndsctl
// Returns downloaded and uploaded in bytes (converted from kilobytes)
// Returns error if client not found or command fails
// This function is thread-safe and serializes ndsctl calls
func GetClientStats(macAddress string) (downloaded uint64, uploaded uint64, err error) {
	// Serialize ndsctl calls to prevent concurrent execution issues
	ndsctlMutex.Lock()
	cmd := exec.Command("ndsctl", "json", macAddress)
	output, err := cmd.Output()
	ndsctlMutex.Unlock() // Unlock immediately after command completes

	if err != nil {
		logger.WithFields(logrus.Fields{
			"mac_address": macAddress,
			"error":       err,
		}).Error("Error executing ndsctl json")
		return 0, 0, fmt.Errorf("failed to execute ndsctl json for MAC %s: %w", macAddress, err)
	}

	// Check for empty response (client not found)
	trimmed := string(output)
	if trimmed == "{}" || trimmed == "{}\n" {
		return 0, 0, fmt.Errorf("client with MAC %s not found in ndsctl", macAddress)
	}

	var stats ClientStats
	err = json.Unmarshal(output, &stats)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"mac_address": macAddress,
			"error":       err,
			"output":      string(output),
		}).Error("Error parsing ndsctl json output")
		return 0, 0, fmt.Errorf("failed to parse ndsctl json for MAC %s: %w", macAddress, err)
	}

	// Convert from kilobytes to bytes
	downloadedBytes := stats.Downloaded * 1024
	uploadedBytes := stats.Uploaded * 1024

	logger.WithFields(logrus.Fields{
		"mac_address":      macAddress,
		"downloaded_kb":    stats.Downloaded,
		"uploaded_kb":      stats.Uploaded,
		"downloaded_bytes": downloadedBytes,
		"uploaded_bytes":   uploadedBytes,
		"state":            stats.State,
	}).Debug("Retrieved client stats from ndsctl")

	return downloadedBytes, uploadedBytes, nil
}

// GetClientUsage returns the total data usage (downloaded + uploaded) for a MAC address
// This is a convenience function that calls GetClientStats
func GetClientUsage(macAddress string) (totalBytes uint64, err error) {
	downloaded, uploaded, err := GetClientStats(macAddress)
	if err != nil {
		return 0, err
	}
	return downloaded + uploaded, nil
}

func delayedAuth(macAddress string) {
	logger.WithFields(logrus.Fields{
		"mac_address": macAddress,
		"delay":       AuthDelay,
	}).Info("Waiting before delayed auth")
	time.Sleep(AuthDelay)

	gatesMutex.Lock()
	untilTimestamp, pending := pendingUntil[macAddress]
	delete(pendingUntil, macAddress)
	gatesMutex.Unlock()

	if !pending {
		logger.WithField("mac_address", macAddress).Warn("Delayed auth has no pending entry, aborting")
		gatesMutex.Lock()
		delete(openGates, macAddress)
		gatesMutex.Unlock()
		return
	}

	if err := authorizeMAC(macAddress); err != nil {
		logger.WithFields(logrus.Fields{
			"mac_address": macAddress,
			"error":       err,
		}).Error("Delayed auth failed")
		gatesMutex.Lock()
		delete(openGates, macAddress)
		gatesMutex.Unlock()
		return
	}

	logger.WithFields(logrus.Fields{
		"mac_address": macAddress,
	}).Info("Delayed auth succeeded")

	remaining := time.Until(time.Unix(untilTimestamp, 0))
	if remaining <= 0 {
		logger.WithField("mac_address", macAddress).Warn("Session expired during auth delay, deauthorizing immediately")
		deauthorizeMAC(macAddress)
		gatesMutex.Lock()
		delete(openGates, macAddress)
		gatesMutex.Unlock()
		return
	}

	timer := time.AfterFunc(remaining, func() {
		if err := deauthorizeMAC(macAddress); err != nil {
			logger.WithField("mac_address", macAddress).Error("Error deauthorizing after timeout")
		}
		gatesMutex.Lock()
		delete(openGates, macAddress)
		gatesMutex.Unlock()
	})

	gatesMutex.Lock()
	openGates[macAddress] = timer
	gatesMutex.Unlock()
}

func delayedAuthIndefinite(macAddress string) {
	logger.WithFields(logrus.Fields{
		"mac_address": macAddress,
		"delay":       AuthDelay,
	}).Info("Waiting before delayed auth")
	time.Sleep(AuthDelay)

	if err := authorizeMAC(macAddress); err != nil {
		logger.WithFields(logrus.Fields{
			"mac_address": macAddress,
			"error":       err,
		}).Error("Delayed auth failed")
		return
	}

	logger.WithFields(logrus.Fields{
		"mac_address": macAddress,
	}).Info("Delayed auth succeeded")

	if err := SetDataBaseline(macAddress); err != nil {
		logger.WithFields(logrus.Fields{
			"mac_address": macAddress,
			"error":       err,
		}).Warn("Failed to set data baseline, continuing anyway")
	}

	gatesMutex.Lock()
	openGates[macAddress] = nil
	gatesMutex.Unlock()
}
