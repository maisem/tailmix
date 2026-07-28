package exitnodeview

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/maisem/tailmix/controlapi"
)

func TestItemsUseTailscaleLocationFiltering(t *testing.T) {
	resource := locationTestResource()

	var got []string
	for _, item := range Items(resource, "") {
		got = append(got, item.Country+"|"+item.City+"|"+item.Node.NodeID)
	}
	want := []string{
		"||legacy",
		"Canada|Any|squamish-high",
		"Canada|Squamish|squamish-high",
		"Canada|Squamish|squamish-selected",
		"Canada|Vancouver|vancouver-high",
		"Germany|Berlin|berlin",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("location-filtered exit nodes:\n got %q\nwant %q", got, want)
	}
}

func TestItemsCountryFilterShowsEveryPeer(t *testing.T) {
	resource := locationTestResource()

	var got []string
	for _, item := range Items(resource, "cAnAdA") {
		got = append(got, item.Country+"|"+item.City+"|"+item.Node.NodeID)
	}
	want := []string{
		"Canada|Squamish|squamish-high",
		"Canada|Squamish|squamish-selected",
		"Canada|Vancouver|vancouver-high",
		"Canada|Vancouver|vancouver-hidden",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("country-filtered exit nodes:\n got %q\nwant %q", got, want)
	}
}

func TestItemsKeepEveryNodeWithoutLocations(t *testing.T) {
	resource := controlapi.ExitNodes{Available: []controlapi.AvailableExitNode{
		{ProfileID: "p1", ProfileName: "work", NodeID: "b", DNSName: "b.example.ts.net", Online: true},
		{ProfileID: "p1", ProfileName: "work", NodeID: "a", DNSName: "a.example.ts.net", Online: true},
	}}
	items := Items(resource, "")
	if len(items) != 2 || items[0].Node.NodeID != "a" || items[1].Node.NodeID != "b" {
		t.Fatalf("unlocated exit nodes = %+v", items)
	}
}

func TestNodesRetainUnavailableSelection(t *testing.T) {
	resource := controlapi.ExitNodes{Selected: &controlapi.SelectedExitNode{
		ProfileID: "p1", ProfileName: "work", NodeID: "old", DNSName: "old.example.ts.net",
		PeerIP: netip.MustParseAddr("100.64.0.20"), State: "waiting", Reason: "exit_node_unavailable",
	}}
	nodes := Nodes(resource)
	if len(nodes) != 1 ||
		!nodes[0].Selected ||
		nodes[0].PeerIP != resource.Selected.PeerIP ||
		nodes[0].Reason != "exit_node_unavailable" {
		t.Fatalf("nodes = %+v", nodes)
	}
}

func TestFilterCountryPreservesFullResourceShape(t *testing.T) {
	resource := locationTestResource()
	filtered := FilterCountry(resource, "Canada")
	if len(filtered.Available) != 4 {
		t.Fatalf("filtered available = %+v", filtered.Available)
	}
	if filtered.Selected == nil || filtered.Selected.NodeID != "squamish-selected" {
		t.Fatalf("filtered selected = %+v", filtered.Selected)
	}
	if got := FilterCountry(resource, "France"); len(got.Available) != 0 || got.Selected != nil {
		t.Fatalf("unexpected France result = %+v", got)
	}
}

func locationTestResource() controlapi.ExitNodes {
	location := func(country, countryCode, city, cityCode string, priority int) *controlapi.ExitNodeLocation {
		return &controlapi.ExitNodeLocation{
			Country: country, CountryCode: countryCode, City: city, CityCode: cityCode, Priority: priority,
		}
	}
	node := func(id, name string, loc *controlapi.ExitNodeLocation) controlapi.AvailableExitNode {
		return controlapi.AvailableExitNode{
			ProfileID: "p1", ProfileName: "work", NodeID: id, DNSName: name, Online: true, Location: loc,
		}
	}
	return controlapi.ExitNodes{
		Available: []controlapi.AvailableExitNode{
			node("legacy", "legacy.example.ts.net", nil),
			node("squamish-high", "squamish-a.example.ts.net", location("Canada", "CA", "Squamish", "YSE", 100)),
			node("squamish-selected", "squamish-b.example.ts.net", location("Canada", "CA", "Squamish", "YSE", 10)),
			node("vancouver-high", "vancouver-a.example.ts.net", location("Canada", "CA", "Vancouver", "YVR", 50)),
			node("vancouver-hidden", "vancouver-b.example.ts.net", location("Canada", "CA", "Vancouver", "YVR", 1)),
			node("berlin", "berlin.example.ts.net", location("Germany", "DE", "Berlin", "BER", 5)),
		},
		Selected: &controlapi.SelectedExitNode{
			ProfileID: "p1", ProfileName: "work", NodeID: "squamish-selected",
			DNSName: "squamish-b.example.ts.net", Online: true,
		},
	}
}
