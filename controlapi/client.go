package controlapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/maisem/tailmix/profilesocket"
	tailmixversion "github.com/maisem/tailmix/version"
)

type Client struct {
	http *http.Client
}

func NewClient(socketDir string) *Client {
	socketPath := profilesocket.ControlPath(socketDir)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{http: &http.Client{Transport: transport}}
}

func (c *Client) Version(ctx context.Context) (tailmixversion.Meta, error) {
	var out tailmixversion.Meta
	err := c.do(ctx, http.MethodGet, "/v1/version", nil, &out)
	return out, err
}

func (c *Client) Status(ctx context.Context) (Status, error) {
	var out Status
	err := c.do(ctx, http.MethodGet, "/v1/status", nil, &out)
	return out, err
}

func (c *Client) UpdateStatus(ctx context.Context) (UpdateStatus, error) {
	var out UpdateStatus
	err := c.do(ctx, http.MethodGet, "/v1/update", nil, &out)
	return out, err
}

func (c *Client) UpdateAction(ctx context.Context, action string) (UpdateStatus, error) {
	var out UpdateStatus
	err := c.do(ctx, http.MethodPost, "/v1/update/"+url.PathEscape(action), nil, &out)
	return out, err
}

func (c *Client) Profiles(ctx context.Context, all bool) (Profiles, error) {
	var out Profiles
	err := c.do(ctx, http.MethodGet, "/v1/profiles?all="+strconv.FormatBool(all), nil, &out)
	return out, err
}

func (c *Client) Profile(ctx context.Context, name string) (Profile, error) {
	var out Profile
	err := c.do(ctx, http.MethodGet, profilePath(name), nil, &out)
	return out, err
}

func (c *Client) AddProfile(ctx context.Context, request AddProfileRequest) (Profile, error) {
	var out Profile
	err := c.do(ctx, http.MethodPost, "/v1/profiles", request, &out)
	return out, err
}

func (c *Client) PatchProfile(ctx context.Context, name string, request PatchProfileRequest) (Profile, error) {
	var out Profile
	err := c.do(ctx, http.MethodPatch, profilePath(name), request, &out)
	return out, err
}

func (c *Client) ProfileAction(ctx context.Context, name, action string) (Profile, error) {
	var out Profile
	err := c.do(ctx, http.MethodPost, profilePath(name)+"/"+action, nil, &out)
	return out, err
}

func (c *Client) RemoveProfile(ctx context.Context, name string, purge bool) (Profile, error) {
	var out Profile
	err := c.do(ctx, http.MethodDelete, profilePath(name)+"?purge="+strconv.FormatBool(purge), nil, &out)
	return out, err
}

func (c *Client) IPRoutes(ctx context.Context, available bool) (IPRoutes, error) {
	path := "/v1/routes"
	if available {
		path += "/available"
	}
	var out IPRoutes
	err := c.do(ctx, http.MethodGet, path, nil, &out)
	return out, err
}

func (c *Client) PatchIPRoutes(ctx context.Context, request PatchIPRoutesRequest) (IPRoutes, error) {
	var out IPRoutes
	err := c.do(ctx, http.MethodPatch, "/v1/routes", request, &out)
	return out, err
}

func (c *Client) ExitNodes(ctx context.Context) (ExitNodes, error) {
	var out ExitNodes
	err := c.do(ctx, http.MethodGet, "/v1/exit-node", nil, &out)
	return out, err
}

func (c *Client) SetExitNode(ctx context.Context, request SetExitNodeRequest) (ExitNodes, error) {
	var out ExitNodes
	err := c.do(ctx, http.MethodPut, "/v1/exit-node", request, &out)
	return out, err
}

func (c *Client) ClearExitNode(ctx context.Context) (ExitNodes, error) {
	var out ExitNodes
	err := c.do(ctx, http.MethodDelete, "/v1/exit-node", nil, &out)
	return out, err
}

func (c *Client) DNSRoutes(ctx context.Context, available bool) (DNSRoutes, error) {
	path := "/v1/dns/routes"
	if available {
		path += "/available"
	}
	var out DNSRoutes
	err := c.do(ctx, http.MethodGet, path, nil, &out)
	return out, err
}

func (c *Client) PatchDNSRoutes(ctx context.Context, request PatchDNSRoutesRequest) (DNSRoutes, error) {
	var out DNSRoutes
	err := c.do(ctx, http.MethodPatch, "/v1/dns/routes", request, &out)
	return out, err
}

func (c *Client) SearchDomains(ctx context.Context) (SearchDomains, error) {
	var out SearchDomains
	err := c.do(ctx, http.MethodGet, "/v1/dns/search-domains", nil, &out)
	return out, err
}

func (c *Client) ReplaceSearchDomains(ctx context.Context, desired []string) (SearchDomains, error) {
	var out SearchDomains
	err := c.do(ctx, http.MethodPut, "/v1/dns/search-domains", ReplaceSearchDomainsRequest{Desired: desired}, &out)
	return out, err
}

func (c *Client) PatchSearchDomains(ctx context.Context, request PatchSearchDomainsRequest) (SearchDomains, error) {
	var out SearchDomains
	err := c.do(ctx, http.MethodPatch, "/v1/dns/search-domains", request, &out)
	return out, err
}

func (c *Client) ClearSearchDomains(ctx context.Context) (SearchDomains, error) {
	var out SearchDomains
	err := c.do(ctx, http.MethodDelete, "/v1/dns/search-domains", nil, &out)
	return out, err
}

func (c *Client) do(ctx context.Context, method, path string, request, response any) error {
	var body io.Reader
	if request != nil {
		var encoded bytes.Buffer
		if err := json.NewEncoder(&encoded).Encode(request); err != nil {
			return err
		}
		body = &encoded
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://tailmix"+path, body)
	if err != nil {
		return err
	}
	if request != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("connect to tailmix daemon: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var apiErr Error
		if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&apiErr); err != nil {
			return fmt.Errorf("tailmix daemon returned %s", res.Status)
		}
		return &apiErr
	}
	if response == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(response); err != nil {
		return fmt.Errorf("decode tailmix daemon response: %w", err)
	}
	return nil
}

func profilePath(name string) string {
	return "/v1/profiles/by-name/" + url.PathEscape(name)
}
