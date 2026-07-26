// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package netns

import (
	"net"
	"testing"

	"tailscale.com/tstest"
)

func TestSetUnderlayInterfaceIndexPublishesInterfaceName(t *testing.T) {
	tstest.Replace(t, &underlayInterfaceByIndex, func(index int) (*net.Interface, error) {
		if index != 12 {
			t.Fatalf("interface index = %d, want 12", index)
		}
		return &net.Interface{Index: index, Name: "en0"}, nil
	})
	var published string
	tstest.Replace(t, &publishUnderlayInterface, func(name string) {
		published = name
	})

	if err := SetUnderlayInterfaceIndex(12); err != nil {
		t.Fatal(err)
	}
	if published != "en0" {
		t.Fatalf("published interface = %q, want en0", published)
	}
}
