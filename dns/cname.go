package dns

import (
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/util/dnsname"
)

// magicDNSTTL matches the TTL tailmix's MagicDNS records use, so a CNAME
// target answered here expires with the effective IP lease it names.
const magicDNSTTL = 600

// maxCNAMEChain bounds how many CNAME records are followed in one answer.
const maxCNAMEChain = 8

// MagicDNSNames answers names that belong to tailmix's MagicDNS: names under
// a profile's MagicDNS suffix, and the exact names of shared-in nodes.
//
// Forwarders use it to finish answers whose CNAME chain ends at such a name.
// Upstream resolvers fill in that name's canonical tailnet address, which
// tailmix does not route. A name identifies the tailnet and node it belongs
// to, so tailmix can answer it with the node's effective IP. A bare address
// in an answer carries no such identity and is never rewritten.
type MagicDNSNames struct {
	suffixes []dnsname.FQDN
	hosts    map[dnsname.FQDN][]netip.Addr
}

// NewMagicDNSNames indexes the MagicDNS domains and records of a DNS config.
func NewMagicDNSNames(domains []Domain, records []Record) *MagicDNSNames {
	m := &MagicDNSNames{hosts: map[dnsname.FQDN][]netip.Addr{}}
	for _, domain := range domains {
		if suffix, err := dnsname.ToFQDN(strings.ToLower(strings.TrimSpace(domain.Suffix))); err == nil && suffix != "." {
			m.suffixes = append(m.suffixes, suffix)
		}
	}
	for _, record := range records {
		name, err := dnsname.ToFQDN(strings.ToLower(strings.TrimSpace(record.Name)))
		if err != nil || name == "." || !record.EffectiveIP.IsValid() {
			continue
		}
		if !containsAddr(m.hosts[name], record.EffectiveIP) {
			m.hosts[name] = append(m.hosts[name], record.EffectiveIP)
		}
	}
	return m
}

// lookup reports the effective IPs of name and whether tailmix answers it.
func (m *MagicDNSNames) lookup(name string) ([]netip.Addr, bool) {
	fqdn, err := dnsname.ToFQDN(strings.ToLower(name))
	if err != nil {
		return nil, false
	}
	if addrs, ok := m.hosts[fqdn]; ok {
		return addrs, true
	}
	for _, suffix := range m.suffixes {
		if suffix.Contains(fqdn) {
			return nil, true
		}
	}
	return nil, false
}

// finishCNAME rewrites an A or AAAA response whose CNAME chain ends at a
// MagicDNS name. It keeps the chain and replaces everything after it with
// the target's effective IPs. Other responses are returned unchanged.
func (m *MagicDNSNames) finishCNAME(response []byte) ([]byte, error) {
	if m == nil {
		return response, nil
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(response); err != nil || len(msg.Questions) != 1 {
		return response, nil
	}
	question := msg.Questions[0]
	if question.Class != dnsmessage.ClassINET || (question.Type != dnsmessage.TypeA && question.Type != dnsmessage.TypeAAAA) {
		return response, nil
	}
	if msg.RCode != dnsmessage.RCodeSuccess && msg.RCode != dnsmessage.RCodeNameError {
		return response, nil
	}
	var chain []dnsmessage.Resource
	target := question.Name
	for len(chain) < maxCNAMEChain {
		next := -1
		for i, rr := range msg.Answers {
			if rr.Header.Type == dnsmessage.TypeCNAME && strings.EqualFold(rr.Header.Name.String(), target.String()) {
				next = i
				break
			}
		}
		if next < 0 {
			break
		}
		chain = append(chain, msg.Answers[next])
		target = msg.Answers[next].Body.(*dnsmessage.CNAMEResource).CNAME
	}
	if len(chain) == 0 {
		return response, nil
	}
	addrs, ok := m.lookup(target.String())
	if !ok {
		return response, nil
	}

	answers := chain
	for _, addr := range addrs {
		header := dnsmessage.ResourceHeader{Name: target, Class: dnsmessage.ClassINET, TTL: magicDNSTTL}
		switch {
		case question.Type == dnsmessage.TypeA && addr.Is4():
			header.Type = dnsmessage.TypeA
			answers = append(answers, dnsmessage.Resource{Header: header, Body: &dnsmessage.AResource{A: addr.As4()}})
		case question.Type == dnsmessage.TypeAAAA && addr.Is6():
			header.Type = dnsmessage.TypeAAAA
			answers = append(answers, dnsmessage.Resource{Header: header, Body: &dnsmessage.AAAAResource{AAAA: addr.As16()}})
		}
	}
	msg.Answers = answers
	// The upstream's authority and additional records describe the answer it
	// gave, not this one. Keep only EDNS options.
	msg.Authorities = nil
	additionals := msg.Additionals[:0]
	for _, rr := range msg.Additionals {
		if rr.Header.Type == dnsmessage.TypeOPT {
			additionals = append(additionals, rr)
		}
	}
	msg.Additionals = additionals
	msg.RCode = dnsmessage.RCodeSuccess
	if len(addrs) == 0 {
		// The name is under a tailmix MagicDNS suffix but has no node.
		msg.RCode = dnsmessage.RCodeNameError
	}
	// Upstream DNSSEC validation does not cover tailmix's records.
	msg.AuthenticData = false
	msg.Authoritative = false
	return msg.Pack()
}
