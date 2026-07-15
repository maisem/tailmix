package status

import (
	"net/netip"
	"testing"

	"github.com/maisem/tailmix/effectiveip"
	"github.com/maisem/tailmix/profile"
)

func TestProjectShowsCanonicalAndEffectiveIPs(t *testing.T) {
	st := Project([]profile.Status{{ProfileID: "work", Alias: "work", SelfNodeID: "self", SelfIPs: []netip.Addr{netip.MustParseAddr("100.64.0.10")}}}, []effectiveip.Lease{{
		NodeKey:     effectiveip.NodeKey{ProfileID: "work", NodeID: "self", CanonicalIP: netip.MustParseAddr("100.64.0.10")},
		EffectiveIP: netip.MustParseAddr("100.127.0.10"),
	}})
	if len(st.Profiles) != 1 {
		t.Fatalf("profile count = %d, want 1", len(st.Profiles))
	}
	got := st.Profiles[0].SelfIPs[0]
	if got.Canonical != "100.64.0.10" || got.Effective != "100.127.0.10" {
		t.Fatalf("self IP projection = %+v", got)
	}
}
