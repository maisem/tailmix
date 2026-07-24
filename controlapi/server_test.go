package controlapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

type recordingBackend struct {
	Backend
	ipPatch  PatchIPRoutesRequest
	profiles Profiles
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
