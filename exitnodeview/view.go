package exitnodeview

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/maisem/tailmix/controlapi"
)

// Node combines an available exit node with its optional selected state.
type Node struct {
	ProfileID   string
	ProfileName string
	NodeID      string
	DNSName     string
	IPs         []netip.Addr
	PeerIP      netip.Addr
	Online      bool
	Location    *controlapi.ExitNodeLocation
	Selected    bool
	State       string
	Reason      string
}

// Key identifies a peer within one tailmix profile.
func (node Node) Key() string {
	return node.ProfileID + "\x00" + node.NodeID
}

// Item is one location-aware display row. A peer can appear twice when it is
// both the best peer for a city and the country-wide Any choice.
type Item struct {
	Node        Node
	Country     string
	CountryCode string
	City        string
	CityCode    string
	Any         bool
}

// Key identifies one display row, including a possible country-wide Any row.
func (item Item) Key() string {
	kind := "city"
	if item.Any {
		kind = "any"
	}
	return strings.Join([]string{
		item.Node.Key(), item.CountryCode, item.Country, kind, item.CityCode, item.City,
	}, "\x00")
}

// Nodes combines available peers with a selected peer that may no longer be
// available.
func Nodes(resource controlapi.ExitNodes) []Node {
	byKey := map[string]Node{}
	for _, available := range resource.Available {
		node := Node{
			ProfileID:   available.ProfileID,
			ProfileName: available.ProfileName,
			NodeID:      available.NodeID,
			DNSName:     available.DNSName,
			IPs:         slices.Clone(available.IPs),
			Online:      available.Online,
			Location:    available.Location,
		}
		byKey[node.Key()] = node
	}
	if selected := resource.Selected; selected != nil {
		key := selected.ProfileID + "\x00" + selected.NodeID
		node, ok := byKey[key]
		if !ok {
			node = Node{
				ProfileID:   selected.ProfileID,
				ProfileName: selected.ProfileName,
				NodeID:      selected.NodeID,
				DNSName:     selected.DNSName,
				Online:      selected.Online,
				Location:    selected.Location,
			}
		}
		node.Selected = true
		node.State = selected.State
		node.Reason = selected.Reason
		node.PeerIP = selected.PeerIP
		if node.DNSName == "" {
			node.DNSName = selected.DNSName
		}
		if node.Location == nil {
			node.Location = selected.Location
		}
		byKey[key] = node
	}

	nodes := make([]Node, 0, len(byKey))
	for _, node := range byKey {
		nodes = append(nodes, node)
	}
	slices.SortFunc(nodes, func(a, b Node) int {
		if byProfile := strings.Compare(strings.ToLower(a.ProfileName), strings.ToLower(b.ProfileName)); byProfile != 0 {
			return byProfile
		}
		if byProfileID := strings.Compare(a.ProfileID, b.ProfileID); byProfileID != 0 {
			return byProfileID
		}
		return compareNodeNames(a, b)
	})
	return nodes
}

// Items mirrors the default `tailscale exit-node list` display. Without a
// country filter it shows the highest-priority peer per located city, retains
// the selected peer, and adds a country-wide Any row when a country has
// multiple cities. With a filter it returns every peer in that country. Peers
// without location metadata are never collapsed.
func Items(resource controlapi.ExitNodes, filterCountry string) []Item {
	filterCountry = strings.TrimSpace(filterCountry)
	nodesByProfile := map[string][]Node{}
	profileNames := map[string]string{}
	for _, node := range Nodes(resource) {
		if filterCountry != "" && !locationMatchesCountry(node.Location, filterCountry) {
			continue
		}
		nodesByProfile[node.ProfileID] = append(nodesByProfile[node.ProfileID], node)
		profileNames[node.ProfileID] = node.ProfileName
	}
	profileIDs := make([]string, 0, len(nodesByProfile))
	for profileID := range nodesByProfile {
		profileIDs = append(profileIDs, profileID)
	}
	slices.SortFunc(profileIDs, func(a, b string) int {
		if byName := strings.Compare(strings.ToLower(profileNames[a]), strings.ToLower(profileNames[b])); byName != 0 {
			return byName
		}
		return strings.Compare(a, b)
	})

	var items []Item
	for _, profileID := range profileIDs {
		nodes := nodesByProfile[profileID]
		slices.SortFunc(nodes, compareNodeNames)
		items = append(items, locationFilteredItems(nodes, filterCountry != "")...)
	}
	return items
}

// FilterCountry returns the full, uncollapsed resource for one country. It is
// useful for preserving the ExitNodes JSON schema when a CLI country filter is
// requested.
func FilterCountry(resource controlapi.ExitNodes, country string) controlapi.ExitNodes {
	country = strings.TrimSpace(country)
	if country == "" {
		return resource
	}
	filtered := controlapi.ExitNodes{ReconcileError: resource.ReconcileError}
	matchedKeys := map[string]bool{}
	for _, node := range resource.Available {
		if !locationMatchesCountry(node.Location, country) {
			continue
		}
		filtered.Available = append(filtered.Available, node)
		matchedKeys[node.ProfileID+"\x00"+node.NodeID] = true
	}
	if selected := resource.Selected; selected != nil {
		key := selected.ProfileID + "\x00" + selected.NodeID
		if matchedKeys[key] || locationMatchesCountry(selected.Location, country) {
			filtered.Selected = selected
		}
	}
	return filtered
}

type countryGroup struct {
	name   string
	code   string
	cities map[string]*cityGroup
}

type cityGroup struct {
	name  string
	code  string
	any   bool
	nodes []Node
}

func locationFilteredItems(nodes []Node, showAll bool) []Item {
	countryGroups := map[string]*countryGroup{}
	for _, node := range nodes {
		countryName, countryCode, cityName, cityCode := "", "", "", ""
		if node.Location != nil {
			countryName = node.Location.Country
			countryCode = node.Location.CountryCode
			cityName = node.Location.City
			cityCode = node.Location.CityCode
		}
		countryKey := "country\x00" + countryCode
		country := countryGroups[countryKey]
		if country == nil {
			country = &countryGroup{
				name: countryName, code: countryCode, cities: map[string]*cityGroup{},
			}
			countryGroups[countryKey] = country
		}
		cityKey := "city\x00" + cityCode
		city := country.cities[cityKey]
		if city == nil {
			city = &cityGroup{name: cityName, code: cityCode}
			country.cities[cityKey] = city
		}
		city.nodes = append(city.nodes, node)
	}

	countries := make([]*countryGroup, 0, len(countryGroups))
	for _, country := range countryGroups {
		countries = append(countries, country)
	}
	slices.SortFunc(countries, func(a, b *countryGroup) int {
		if byName := strings.Compare(a.name, b.name); byName != 0 {
			return byName
		}
		return strings.Compare(a.code, b.code)
	})

	var items []Item
	for _, country := range countries {
		cities := make([]*cityGroup, 0, len(country.cities))
		for _, city := range country.cities {
			cities = append(cities, city)
		}
		slices.SortFunc(cities, func(a, b *cityGroup) int {
			if byName := strings.Compare(a.name, b.name); byName != 0 {
				return byName
			}
			return strings.Compare(a.code, b.code)
		})

		if country.name != "" && !showAll {
			var countryNodes []Node
			for _, city := range cities {
				slices.SortStableFunc(city.nodes, compareNodePriority)
				countryNodes = append(countryNodes, city.nodes...)
				reduced := city.nodes[:0]
				for i, node := range city.nodes {
					if i == 0 || node.Selected {
						reduced = append(reduced, node)
					}
				}
				city.nodes = reduced
			}
			slices.SortStableFunc(countryNodes, compareNodePriority)
			if len(cities) > 1 {
				cities = append([]*cityGroup{{
					name: "Any", any: true, nodes: countryNodes[:1],
				}}, cities...)
			}
		}

		for _, city := range cities {
			for _, node := range city.nodes {
				items = append(items, Item{
					Node: node, Country: country.name, CountryCode: country.code,
					City: city.name, CityCode: city.code, Any: city.any,
				})
			}
		}
	}
	return items
}

func locationMatchesCountry(location *controlapi.ExitNodeLocation, country string) bool {
	return location != nil && strings.EqualFold(location.Country, country)
}

func compareNodeNames(a, b Node) int {
	if byName := strings.Compare(a.DNSName, b.DNSName); byName != 0 {
		return byName
	}
	return strings.Compare(a.NodeID, b.NodeID)
}

func compareNodePriority(a, b Node) int {
	aPriority, bPriority := 0, 0
	if a.Location != nil {
		aPriority = a.Location.Priority
	}
	if b.Location != nil {
		bPriority = b.Location.Priority
	}
	if aPriority < bPriority {
		return 1
	}
	if aPriority > bPriority {
		return -1
	}
	return compareNodeNames(a, b)
}
