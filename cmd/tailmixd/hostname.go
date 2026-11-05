package main

import (
	"os"
	"strings"

	"tailscale.com/util/dnsname"
)

// osHostname reports the machine's hostname. It is a variable so tests can
// stub the host name without changing the OS.
var osHostname = os.Hostname

// sanitizeHostname converts a raw OS hostname into the short, lower-case DNS
// label tailmix advertises to a tailnet. It keeps only the first DNS label so
// an FQDN such as "laptop.example.com" becomes "laptop" rather than
// "laptop-example-com", then applies Tailscale's hostname sanitization.
func sanitizeHostname(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	return dnsname.SanitizeHostname(dnsname.FirstLabel(trimmed))
}

// defaultHostname returns the sanitized machine hostname, or empty when it is
// unavailable or sanitizes to nothing. Callers fall back to a generated
// tailmix- name in that case.
func defaultHostname() string {
	name, err := osHostname()
	if err != nil {
		return ""
	}
	return sanitizeHostname(name)
}
