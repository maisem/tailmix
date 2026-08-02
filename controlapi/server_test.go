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
)

type recordingBackend struct {
	Backend
	ipPatch      PatchIPRoutesRequest
	exitRequest  SetExitNodeRequest
	profiles     Profiles
	status       Status
	update       UpdateStatus
	updateAction string
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

func TestHandlerReturnsAggregateStatus(t *testing.T) {
	backend := &recordingBackend{status: Status{
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
	if len(got.Profiles) != 1 || got.Profiles[0].Name != "work" ||
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
