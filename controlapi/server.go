package controlapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"

	tailmixversion "github.com/maisem/tailmix/version"
)

type Backend interface {
	Status(context.Context) (Status, error)
	ListProfiles(context.Context, bool) (Profiles, error)
	GetProfile(context.Context, string) (Profile, error)
	AddProfile(context.Context, AddProfileRequest) (Profile, error)
	PatchProfile(context.Context, string, PatchProfileRequest) (Profile, error)
	SetProfileEnabled(context.Context, string, bool) (Profile, error)
	RestartProfile(context.Context, string) (Profile, error)
	RemoveProfile(context.Context, string, bool) (Profile, error)

	IPRoutes(context.Context, bool) (IPRoutes, error)
	PatchIPRoutes(context.Context, PatchIPRoutesRequest) (IPRoutes, error)
	ReplaceIPRoutes(context.Context, ReplaceIPRoutesRequest) (IPRoutes, error)
	ClearIPRoutes(context.Context) (IPRoutes, error)

	ExitNodes(context.Context) (ExitNodes, error)
	SetExitNode(context.Context, SetExitNodeRequest) (ExitNodes, error)
	ClearExitNode(context.Context) (ExitNodes, error)

	DNSRoutes(context.Context, bool) (DNSRoutes, error)
	PatchDNSRoutes(context.Context, PatchDNSRoutesRequest) (DNSRoutes, error)
	ReplaceDNSRoutes(context.Context, ReplaceDNSRoutesRequest) (DNSRoutes, error)
	ClearDNSRoutes(context.Context) (DNSRoutes, error)

	SearchDomains(context.Context) (SearchDomains, error)
	PatchSearchDomains(context.Context, PatchSearchDomainsRequest) (SearchDomains, error)
	ReplaceSearchDomains(context.Context, ReplaceSearchDomainsRequest) (SearchDomains, error)
	ClearSearchDomains(context.Context) (SearchDomains, error)
}

func Handler(backend Backend) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/version", func(w http.ResponseWriter, _ *http.Request) {
		writeResult(w, tailmixversion.GetMeta(), nil)
	})
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		result, err := backend.Status(r.Context())
		writeResult(w, result, err)
	})
	mux.HandleFunc("GET /v1/profiles", func(w http.ResponseWriter, r *http.Request) {
		all, _ := strconv.ParseBool(r.URL.Query().Get("all"))
		result, err := backend.ListProfiles(r.Context(), all)
		writeResult(w, result, err)
	})
	mux.HandleFunc("POST /v1/profiles", func(w http.ResponseWriter, r *http.Request) {
		var request AddProfileRequest
		if !decodeRequest(w, r, &request) {
			return
		}
		result, err := backend.AddProfile(r.Context(), request)
		writeResult(w, result, err)
	})
	mux.HandleFunc("GET /v1/profiles/by-name/{name}", func(w http.ResponseWriter, r *http.Request) {
		name, err := url.PathUnescape(r.PathValue("name"))
		if err != nil {
			writeResult(w, nil, NewError("invalid_request", "invalid escaped profile name"))
			return
		}
		result, backendErr := backend.GetProfile(r.Context(), name)
		writeResult(w, result, backendErr)
	})
	mux.HandleFunc("PATCH /v1/profiles/by-name/{name}", func(w http.ResponseWriter, r *http.Request) {
		name, err := url.PathUnescape(r.PathValue("name"))
		if err != nil {
			writeResult(w, nil, NewError("invalid_request", "invalid escaped profile name"))
			return
		}
		var request PatchProfileRequest
		if !decodeRequest(w, r, &request) {
			return
		}
		result, backendErr := backend.PatchProfile(r.Context(), name, request)
		writeResult(w, result, backendErr)
	})
	for _, action := range []string{"enable", "disable", "restart"} {
		mux.HandleFunc("POST /v1/profiles/by-name/{name}/"+action, profileActionHandler(backend, action))
	}
	mux.HandleFunc("DELETE /v1/profiles/by-name/{name}", func(w http.ResponseWriter, r *http.Request) {
		name, err := url.PathUnescape(r.PathValue("name"))
		if err != nil {
			writeResult(w, nil, NewError("invalid_request", "invalid escaped profile name"))
			return
		}
		purge, _ := strconv.ParseBool(r.URL.Query().Get("purge"))
		result, backendErr := backend.RemoveProfile(r.Context(), name, purge)
		writeResult(w, result, backendErr)
	})

	mux.HandleFunc("GET /v1/routes", func(w http.ResponseWriter, r *http.Request) {
		result, err := backend.IPRoutes(r.Context(), false)
		writeResult(w, result, err)
	})
	mux.HandleFunc("GET /v1/routes/available", func(w http.ResponseWriter, r *http.Request) {
		result, err := backend.IPRoutes(r.Context(), true)
		writeResult(w, result, err)
	})
	mux.HandleFunc("PUT /v1/routes", func(w http.ResponseWriter, r *http.Request) {
		var request ReplaceIPRoutesRequest
		if !decodeRequest(w, r, &request) {
			return
		}
		result, err := backend.ReplaceIPRoutes(r.Context(), request)
		writeResult(w, result, err)
	})
	mux.HandleFunc("PATCH /v1/routes", func(w http.ResponseWriter, r *http.Request) {
		var request PatchIPRoutesRequest
		if !decodeRequest(w, r, &request) {
			return
		}
		result, err := backend.PatchIPRoutes(r.Context(), request)
		writeResult(w, result, err)
	})
	mux.HandleFunc("DELETE /v1/routes", func(w http.ResponseWriter, r *http.Request) {
		result, err := backend.ClearIPRoutes(r.Context())
		writeResult(w, result, err)
	})

	mux.HandleFunc("GET /v1/exit-node", func(w http.ResponseWriter, r *http.Request) {
		result, err := backend.ExitNodes(r.Context())
		writeResult(w, result, err)
	})
	mux.HandleFunc("PUT /v1/exit-node", func(w http.ResponseWriter, r *http.Request) {
		var request SetExitNodeRequest
		if !decodeRequest(w, r, &request) {
			return
		}
		result, err := backend.SetExitNode(r.Context(), request)
		writeResult(w, result, err)
	})
	mux.HandleFunc("DELETE /v1/exit-node", func(w http.ResponseWriter, r *http.Request) {
		result, err := backend.ClearExitNode(r.Context())
		writeResult(w, result, err)
	})

	mux.HandleFunc("GET /v1/dns/routes", func(w http.ResponseWriter, r *http.Request) {
		result, err := backend.DNSRoutes(r.Context(), false)
		writeResult(w, result, err)
	})
	mux.HandleFunc("GET /v1/dns/routes/available", func(w http.ResponseWriter, r *http.Request) {
		result, err := backend.DNSRoutes(r.Context(), true)
		writeResult(w, result, err)
	})
	mux.HandleFunc("PUT /v1/dns/routes", func(w http.ResponseWriter, r *http.Request) {
		var request ReplaceDNSRoutesRequest
		if !decodeRequest(w, r, &request) {
			return
		}
		result, err := backend.ReplaceDNSRoutes(r.Context(), request)
		writeResult(w, result, err)
	})
	mux.HandleFunc("PATCH /v1/dns/routes", func(w http.ResponseWriter, r *http.Request) {
		var request PatchDNSRoutesRequest
		if !decodeRequest(w, r, &request) {
			return
		}
		result, err := backend.PatchDNSRoutes(r.Context(), request)
		writeResult(w, result, err)
	})
	mux.HandleFunc("DELETE /v1/dns/routes", func(w http.ResponseWriter, r *http.Request) {
		result, err := backend.ClearDNSRoutes(r.Context())
		writeResult(w, result, err)
	})

	mux.HandleFunc("GET /v1/dns/search-domains", func(w http.ResponseWriter, r *http.Request) {
		result, err := backend.SearchDomains(r.Context())
		writeResult(w, result, err)
	})
	mux.HandleFunc("PUT /v1/dns/search-domains", func(w http.ResponseWriter, r *http.Request) {
		var request ReplaceSearchDomainsRequest
		if !decodeRequest(w, r, &request) {
			return
		}
		result, err := backend.ReplaceSearchDomains(r.Context(), request)
		writeResult(w, result, err)
	})
	mux.HandleFunc("PATCH /v1/dns/search-domains", func(w http.ResponseWriter, r *http.Request) {
		var request PatchSearchDomainsRequest
		if !decodeRequest(w, r, &request) {
			return
		}
		result, err := backend.PatchSearchDomains(r.Context(), request)
		writeResult(w, result, err)
	})
	mux.HandleFunc("DELETE /v1/dns/search-domains", func(w http.ResponseWriter, r *http.Request) {
		result, err := backend.ClearSearchDomains(r.Context())
		writeResult(w, result, err)
	})
	return mux
}

func profileActionHandler(backend Backend, action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name, err := url.PathUnescape(r.PathValue("name"))
		if err != nil {
			writeResult(w, nil, NewError("invalid_request", "invalid escaped profile name"))
			return
		}
		var result Profile
		switch action {
		case "enable":
			result, err = backend.SetProfileEnabled(r.Context(), name, true)
		case "disable":
			result, err = backend.SetProfileEnabled(r.Context(), name, false)
		case "restart":
			result, err = backend.RestartProfile(r.Context(), name)
		}
		writeResult(w, result, err)
	}
}

func decodeRequest(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeResult(w, nil, NewError("invalid_request", "decode request: %v", err))
		return false
	}
	if decoder.Decode(new(any)) != io.EOF {
		writeResult(w, nil, NewError("invalid_request", "request must contain one JSON value"))
		return false
	}
	return true
}

func writeResult(w http.ResponseWriter, result any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		var apiErr *Error
		if !errors.As(err, &apiErr) {
			apiErr = NewError("internal_error", "%v", err)
		}
		status := http.StatusBadRequest
		switch apiErr.Code {
		case "profile_not_found":
			status = http.StatusNotFound
		case "profile_exists", "profile_disabled", "transition_in_progress",
			"route_binding_conflict", "dns_route_binding_conflict",
			"binding_profile_mismatch", "profile_has_bindings":
			status = http.StatusConflict
		case "permission_denied":
			status = http.StatusForbidden
		case "internal_error", "runtime_start_failed", "dns_configuration_failed",
			"reconcile_failed", "purge_failed":
			status = http.StatusInternalServerError
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(apiErr)
		return
	}
	_ = json.NewEncoder(w).Encode(result)
}
