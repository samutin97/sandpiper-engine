package adminbgservice

import (
	"encoding/json"
	"fmt"
)

// privilegedOnlyKeys are the app settings the engine the service runs as SYSTEM or root never
// takes from a request (B-01): enable-full-config lets the profile's own inbounds, DNS and routes
// through (a listener of its choice, opened with the service's rights), and log-file makes the
// engine write its log to any path. The app never sends either for VPN mode.
var privilegedOnlyKeys = []string{"enable-full-config", "log-file"}

// privilegedSettings returns the request's settings without privilegedOnlyKeys; "{}" when empty.
func privilegedSettings(settingsJSON string) (string, error) {
	if settingsJSON == "" {
		return "{}", nil
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(settingsJSON), &settings); err != nil {
		return "", fmt.Errorf("invalid VPN settings: %w", err)
	}
	if settings == nil {
		return "{}", nil
	}
	for _, key := range privilegedOnlyKeys {
		delete(settings, key)
	}
	cleaned, err := json.Marshal(settings)
	if err != nil {
		return "", err
	}
	return string(cleaned), nil
}
