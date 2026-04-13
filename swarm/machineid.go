package swarm

// Machine identity helpers for zero-touch endpoint enrollment.
//
// Fingerprint = HMAC-SHA256(machine_id || primary_MAC, local_id + "|" + role)
// encoded as base62. Stable across restarts, unique per (machine, local_id, role).

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net"
	"strings"

	"github.com/denisbrodbeck/machineid"
)

const base62Dict = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Virtual/tunnel interface prefixes to skip when picking primary MAC.
var skipIfacePrefixes = []string{
	"docker", "veth", "br-", "virbr", "vboxnet", "lxcbr",
	"tailscale", "wg", "tun", "tap", "zt", "cni",
}

// Wired Ethernet name prefixes (Linux systemd predictable names + legacy).
var wiredIfacePrefixes = []string{"eth", "eno", "enp", "ens", "enx"}

// MachineID returns a stable, OS-level machine identifier, salted with the
// swarm app name. Safe to call repeatedly — returns the same value per machine.
func MachineID() (string, error) {
	id, err := machineid.ProtectedID("gole-swarm@wixcloud.de")
	if err != nil {
		return "", fmt.Errorf("machine id: %w", err)
	}
	return id, nil
}

// PrimaryMAC returns the MAC address of the primary wired Ethernet interface.
// Preference order:
//  1. Up interfaces with wired names (eth*, eno*, enp*, ens*, enx*)
//  2. Any up, non-loopback, non-virtual interface with a HW address
//
// Returns empty string (no error) if no suitable interface is found —
// fingerprint will still work without a MAC, just less unique.
func PrimaryMAC() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("enumerate interfaces: %w", err)
	}

	var fallback string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		if isSkippedIface(iface.Name) {
			continue
		}

		if isWiredIface(iface.Name) {
			return iface.HardwareAddr.String(), nil
		}
		if fallback == "" {
			fallback = iface.HardwareAddr.String()
		}
	}

	return fallback, nil
}

// Fingerprint builds a stable identity string from machine_id, primary MAC,
// local_id, and role. Empty local_id is allowed (single-instance case).
func Fingerprint(machineID, mac, localID, role string) string {
	key := []byte(machineID + "|" + mac)
	msg := []byte(localID + "|" + role)

	mac2 := hmac.New(sha256.New, key)
	mac2.Write(msg)
	sum := mac2.Sum(nil)

	return bytesToBase62(sum)
}

// DeriveFingerprint is a convenience that derives MachineID and PrimaryMAC
// at runtime and combines them with local_id and role.
func DeriveFingerprint(localID, role string) (string, error) {
	mid, err := MachineID()
	if err != nil {
		return "", err
	}
	mac, _ := PrimaryMAC() // empty MAC is acceptable
	return Fingerprint(mid, mac, localID, role), nil
}

// --- helpers ---

func isSkippedIface(name string) bool {
	n := strings.ToLower(name)
	for _, p := range skipIfacePrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	// wifi prefixes
	if strings.HasPrefix(n, "wlan") || strings.HasPrefix(n, "wlp") || strings.HasPrefix(n, "wifi") {
		return true
	}
	return false
}

func isWiredIface(name string) bool {
	n := strings.ToLower(name)
	for _, p := range wiredIfacePrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// bytesToBase62 encodes bytes as base62 (compact, URL-safe, no padding).
func bytesToBase62(b []byte) string {
	dictLen := len(base62Dict)
	var sb strings.Builder
	sb.Grow(len(b))
	for _, x := range b {
		sb.WriteByte(base62Dict[int(x)%dictLen])
	}
	return sb.String()
}
