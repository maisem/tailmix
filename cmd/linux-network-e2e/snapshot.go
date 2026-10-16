//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"sort"
	"time"
)

// This is the caller namespace, not an assertion about an inaccessible outer
// Docker host. Values are compared privately and are never printed.
type snapshot struct {
	addresses string
	routes    string
	dns       [32]byte
}

func hostSnapshot(r runner) snapshot {
	run := func(args ...string) result {
		return must(r.run(command{argv: append([]string{"ip"}, args...), timeout: 10 * time.Second}))
	}
	var addresses []struct {
		Ifname   string
		AddrInfo []struct {
			Family    string
			Local     string
			Prefixlen int
		} `json:"addr_info"`
	}
	require(json.Unmarshal([]byte(run("-j", "address").stdout), &addresses) == nil, "caller address snapshot")
	addressLines := []string{}
	for _, iface := range addresses {
		for _, addr := range iface.AddrInfo {
			line := must(json.Marshal([]any{iface.Ifname, addr.Family, addr.Local, addr.Prefixlen}))
			addressLines = append(addressLines, string(line))
		}
	}
	sort.Strings(addressLines)
	routes := []string{}
	for _, family := range []string{"-4", "-6"} {
		var values []map[string]json.RawMessage
		require(json.Unmarshal([]byte(run("-j", family, "route", "show", "table", "all").stdout), &values) == nil, "caller route snapshot")
		for _, value := range values {
			delete(value, "expires")
			delete(value, "cache")
			delete(value, "age")
			routes = append(routes, family+string(must(json.Marshal(value))))
		}
	}
	sort.Strings(routes)
	dns := must(os.ReadFile("/etc/resolv.conf"))
	return snapshot{
		string(must(json.Marshal(addressLines))),
		string(must(json.Marshal(routes))),
		sha256.Sum256(dns),
	}
}
