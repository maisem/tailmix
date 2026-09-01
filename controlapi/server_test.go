package controlapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	tailmixversion "github.com/maisem/tailmix/version"
	"github.com/maisem/tailmix/wireguardcfg"
)

type recordingBackend struct {
	Backend
	daemonUp         bool
	ipPatch          PatchIPRoutesRequest
	exitRequest      SetExitNodeRequest
	profiles         Profiles
	status           Status
	update           UpdateStatus
	updateAction     string
	wireGuardConfig  wireguardcfg.Config
	wireGuardSecrets wireguardcfg.Secrets
	wireGuardProfile WireGuardProfile
	wireGuardName    string
	wireGuardShields bool
}

func (b *recordingBackend) UpdateStatus(context.Context) (UpdateStatus, error) { return b.update, nil }
func (b *recordingBackend) SetUpdatesEnabled(_ context.Context, enabled bool) (UpdateStatus, error) {
	if enabled {
		b.updateAction = "enable"
	} else {
		b.updateAction = "disable"
	}
	b.update.Enabled = enabled
	return b.update, nil
}
func (b *recordingBackend) CheckForUpdate(context.Context) (UpdateStatus, error) {
	b.updateAction = "check"
	return b.update, nil
}
func (b *recordingBackend) ApplyUpdate(context.Context) (UpdateStatus, error) {
	b.updateAction = "apply"
	return b.update, nil
}

func (b *recordingBackend) Status(context.Context) (Status, error) {
	return b.status, nil
}

func (b *recordingBackend) SetDaemonUp(_ context.Context, up bool) (DaemonState, error) {
	b.daemonUp = up
	state := "down"
	if up {
		state = "up"
	}
	return DaemonState{State: state}, nil
}

func (b *recordingBackend) PatchIPRoutes(_ context.Context, request PatchIPRoutesRequest) (IPRoutes, error) {
	b.ipPatch = request
	return IPRoutes{Bindings: []IPRouteBinding{{
		Prefix:      request.Bind[0].Prefix,
		ProfileName: request.Bind[0].ProfileName,
		State:       "installed",
	}}}, nil
}

func (b *recordingBackend) ListProfiles(context.Context, bool) (Profiles, error) {
	return b.profiles, nil
}

func (b *recordingBackend) SetExitNode(_ context.Context, request SetExitNodeRequest) (ExitNodes, error) {
	b.exitRequest = request
	return ExitNodes{Selected: &SelectedExitNode{
		ProfileName: request.ProfileName,
		DNSName:     request.Peer,
		State:       "installed",
	}}, nil
}

func (b *recordingBackend) ApplyWireGuard(_ context.Context, config wireguardcfg.Config, secrets wireguardcfg.Secrets) (WireGuardProfile, error) {
	b.wireGuardConfig = config
	b.wireGuardSecrets = secrets
	return b.wireGuardProfile, nil
}

func (b *recordingBackend) WireGuardProfile(_ context.Context, name string) (WireGuardProfile, error) {
	b.wireGuardName = name
	return b.wireGuardProfile, nil
}

func (b *recordingBackend) SetWireGuardShieldsUp(_ context.Context, name string, enabled bool) (WireGuardProfile, error) {
	b.wireGuardName = name
	b.wireGuardShields = enabled
	b.wireGuardProfile.ShieldsUp = enabled
	return b.wireGuardProfile, nil
}

func TestHandlerReturnsServerVersion(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/v1/version", nil)
	response := httptest.NewRecorder()
	Handler(&recordingBackend{}).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var got tailmixversion.Meta
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Short == "" || got.Long == "" || got.TailscaleVersion == "" {
		t.Fatalf("version = %+v", got)
	}
}

func TestHandlerChangesDaemonState(t *testing.T) {
	for _, test := range []struct {
		path string
		up   bool
	}{
		{path: "/v1/up", up: true},
		{path: "/v1/down", up: false},
	} {
		t.Run(test.path, func(t *testing.T) {
			backend := &recordingBackend{}
			response := httptest.NewRecorder()
			Handler(backend).ServeHTTP(response, httptest.NewRequest(http.MethodPost, test.path, nil))
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			if backend.daemonUp != test.up {
				t.Fatalf("daemon up = %v, want %v", backend.daemonUp, test.up)
			}
			var got DaemonState
			if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			want := "down"
			if test.up {
				want = "up"
			}
			if got.State != want {
				t.Fatalf("state = %q, want %q", got.State, want)
			}
		})
	}
}

func TestHandlerAppliesAndShowsWireGuardProfile(t *testing.T) {
	private, err := wireguardcfg.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	backend := &recordingBackend{wireGuardProfile: WireGuardProfile{
		Name: "lab", Kind: "wireguard", PublicKey: "public",
		Peers: []WireGuardPeer{{Name: "peer", PublicKey: "peer-public", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}},
	}}
	body, err := json.Marshal(ApplyWireGuardRequest{
		Config:  wireguardcfg.Config{Version: 1, Name: "lab", DNSSuffix: "wg.example", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}},
		Secrets: wireguardcfg.Secrets{PrivateKey: &private},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	Handler(backend).ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/wireguard", strings.NewReader(string(body))))
	if response.Code != http.StatusOK || backend.wireGuardConfig.Name != "lab" || backend.wireGuardSecrets.PrivateKey == nil || *backend.wireGuardSecrets.PrivateKey != private {
		t.Fatalf("status = %d, config = %+v, secrets = %+v, body = %s", response.Code, backend.wireGuardConfig, backend.wireGuardSecrets, response.Body.String())
	}
	if strings.Contains(response.Body.String(), private.String()) {
		t.Fatalf("response exposed private key: %s", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "lastHandshake") || !strings.Contains(response.Body.String(), `"canonicalAddresses":["10.0.0.2"]`) {
		t.Fatalf("response did not preserve optional/runtime address contract: %s", response.Body.String())
	}

	response = httptest.NewRecorder()
	Handler(backend).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/wireguard/by-name/lab", nil))
	if response.Code != http.StatusOK || backend.wireGuardName != "lab" || !strings.Contains(response.Body.String(), `"kind":"wireguard"`) {
		t.Fatalf("status = %d, name = %q, body = %s", response.Code, backend.wireGuardName, response.Body.String())
	}

	response = httptest.NewRecorder()
	Handler(backend).ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/wireguard/by-name/lab/shields-up", strings.NewReader(`{"enabled":true}`)))
	if response.Code != http.StatusOK || backend.wireGuardName != "lab" || !backend.wireGuardShields || !strings.Contains(response.Body.String(), `"shieldsUp":true`) {
		t.Fatalf("status = %d, name = %q, enabled = %v, body = %s", response.Code, backend.wireGuardName, backend.wireGuardShields, response.Body.String())
	}
}

func TestHandlerReturnsAggregateStatus(t *testing.T) {
	backend := &recordingBackend{status: Status{
		State:    "down",
		Profiles: []Profile{{Name: "work"}},
		DNSRoutes: DNSRoutes{Automatic: []DNSRouteBinding{{
			Domain: "work.example", ProfileName: "work", State: "installed",
		}}},
	}}
	request := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	response := httptest.NewRecorder()
	Handler(backend).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var got Status
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.State != "down" || len(got.Profiles) != 1 || got.Profiles[0].Name != "work" ||
		len(got.DNSRoutes.Automatic) != 1 || got.DNSRoutes.Automatic[0].Domain != "work.example" {
		t.Fatalf("aggregate status = %+v", got)
	}
}

func TestHandlerUpdateEndpoints(t *testing.T) {
	for _, tc := range []struct{ path, action string }{
		{"/v1/update/enable", "enable"},
		{"/v1/update/disable", "disable"},
		{"/v1/update/check", "check"},
		{"/v1/update/apply", "apply"},
	} {
		t.Run(tc.action, func(t *testing.T) {
			backend := &recordingBackend{update: UpdateStatus{CurrentVersion: "1.2.3", State: "idle"}}
			response := httptest.NewRecorder()
			Handler(backend).ServeHTTP(response, httptest.NewRequest(http.MethodPost, tc.path, nil))
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			if backend.updateAction != tc.action {
				t.Fatalf("action = %q", backend.updateAction)
			}
		})
	}
	backend := &recordingBackend{update: UpdateStatus{Enabled: true, State: "idle"}}
	response := httptest.NewRecorder()
	Handler(backend).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/update", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	var got UpdateStatus
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Enabled {
		t.Fatalf("status = %+v", got)
	}
}

func TestHandlerDecodesAtomicRoutePatch(t *testing.T) {
	backend := &recordingBackend{}
	request := httptest.NewRequest(http.MethodPatch, "/v1/routes", strings.NewReader(`{
		"bind":[{"prefix":"10.20.0.0/16","profileName":"work"}],
		"acceptAll":{"home":true}
	}`))
	response := httptest.NewRecorder()
	Handler(backend).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if len(backend.ipPatch.Bind) != 1 ||
		backend.ipPatch.Bind[0].Prefix != netip.MustParsePrefix("10.20.0.0/16") ||
		backend.ipPatch.Bind[0].ProfileName != "work" ||
		!backend.ipPatch.AcceptAll["home"] {
		t.Fatalf("patch = %+v", backend.ipPatch)
	}
	var got IPRoutes
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Bindings[0].State != "installed" {
		t.Fatalf("response = %+v", got)
	}
}

func TestHandlerRejectsUnknownRequestFields(t *testing.T) {
	backend := &recordingBackend{}
	request := httptest.NewRequest(http.MethodPatch, "/v1/routes", strings.NewReader(`{"surprise":true}`))
	response := httptest.NewRecorder()
	Handler(backend).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var got Error
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Code != "invalid_request" {
		t.Fatalf("error = %+v", got)
	}
}

func TestHandlerSetsExitNode(t *testing.T) {
	backend := &recordingBackend{}
	request := httptest.NewRequest(http.MethodPut, "/v1/exit-node", strings.NewReader(`{
		"profileName":"work",
		"peer":"gateway"
	}`))
	response := httptest.NewRecorder()
	Handler(backend).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if backend.exitRequest.ProfileName != "work" || backend.exitRequest.Peer != "gateway" {
		t.Fatalf("request = %+v", backend.exitRequest)
	}
	var got ExitNodes
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Selected == nil || got.Selected.State != "installed" {
		t.Fatalf("response = %+v", got)
	}
}

func TestHandlerRejectsRemovedProfileControlURL(t *testing.T) {
	backend := &recordingBackend{}
	request := httptest.NewRequest(http.MethodPost, "/v1/profiles", strings.NewReader(`{
		"name":"work",
		"controlUrl":"https://headscale.example.com"
	}`))
	response := httptest.NewRecorder()
	Handler(backend).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var got Error
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Code != "invalid_request" {
		t.Fatalf("error = %+v", got)
	}
}

func TestHandlerMapsDaemonDownToHTTPConflict(t *testing.T) {
	backend := &daemonDownBackend{recordingBackend: recordingBackend{}}
	request := httptest.NewRequest(http.MethodPost, "/v1/profiles", strings.NewReader(`{"name":"work"}`))
	response := httptest.NewRecorder()
	Handler(backend).ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var got Error
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Code != "daemon_down" {
		t.Fatalf("error = %+v", got)
	}
}

type daemonDownBackend struct {
	recordingBackend
}

func (b *daemonDownBackend) AddProfile(context.Context, AddProfileRequest) (Profile, error) {
	return Profile{}, NewError("daemon_down", "tailmix is down")
}

func TestHandlerMapsConflictsToHTTPConflict(t *testing.T) {
	backend := &conflictBackend{recordingBackend: recordingBackend{}}
	request := httptest.NewRequest(http.MethodPatch, "/v1/routes", strings.NewReader(`{
		"bind":[{"prefix":"10.20.0.0/16","profileName":"work"}]
	}`))
	response := httptest.NewRecorder()
	Handler(backend).ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

type conflictBackend struct {
	recordingBackend
}

func (b *conflictBackend) PatchIPRoutes(context.Context, PatchIPRoutesRequest) (IPRoutes, error) {
	return IPRoutes{}, NewError("route_binding_conflict", "already bound")
}
