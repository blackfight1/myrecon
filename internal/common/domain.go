package common

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// EffectiveRootDomain returns eTLD+1 when possible, falling back to the last
// two labels for non-standard hosts.
func EffectiveRootDomain(host string) string {
	h := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(host, ".")))
	if h == "" {
		return ""
	}
	if root, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil && root != "" {
		return root
	}
	parts := strings.Split(h, ".")
	if len(parts) < 2 {
		return h
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}
