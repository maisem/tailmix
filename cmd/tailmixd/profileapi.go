package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	tailmixprofile "github.com/maisem/tailmix/profile"
	"github.com/maisem/tailmix/profilesocket"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/safesocket"
	"tailscale.com/types/logid"
)

type profileAPIServer struct {
	cancel context.CancelFunc
	done   chan error
}

type profileAPIGroup struct {
	servers []profileAPIServer
	errs    chan error
}

func startProfileAPIs(ctx context.Context, dir string, profiles []runtimeProfile, stderr io.Writer) (*profileAPIGroup, error) {
	group := &profileAPIGroup{errs: make(chan error, max(1, len(profiles)))}
	for _, rp := range profiles {
		provider, ok := rp.Engine.(tailmixprofile.LocalBackendProvider)
		if !ok {
			_ = group.Close()
			return nil, fmt.Errorf("profile %q engine does not expose its LocalBackend", rp.State.ID)
		}
		backend, err := provider.LocalBackend()
		if err != nil {
			_ = group.Close()
			return nil, fmt.Errorf("profile %q LocalBackend: %w", rp.State.ID, err)
		}
		path, err := profilesocket.Path(dir, rp.State.ID)
		if err != nil {
			_ = group.Close()
			return nil, err
		}
		listener, err := safesocket.Listen(path)
		if err != nil {
			_ = group.Close()
			return nil, fmt.Errorf("listen on profile %q LocalAPI socket %s: %w", rp.State.ID, path, err)
		}

		logf := prefixedLogf(stderr, rp.State.ID+"-api")
		server := ipnserver.New(logf, logid.PublicID{}, backend.EventBus(), backend.NetMon())
		server.SetLocalBackend(backend)
		serverCtx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		group.servers = append(group.servers, profileAPIServer{cancel: cancel, done: done})
		fmt.Fprintf(stderr, "profile %s LocalAPI socket %s\n", rp.State.ID, path)
		go func(profileID string) {
			err := server.Run(serverCtx, listener)
			done <- err
			if err != nil && serverCtx.Err() == nil {
				select {
				case group.errs <- fmt.Errorf("serve profile %q LocalAPI: %w", profileID, err):
				case <-ctx.Done():
				}
			}
		}(rp.State.ID)
	}
	return group, nil
}

func (g *profileAPIGroup) Errors() <-chan error { return g.errs }

func (g *profileAPIGroup) Close() error {
	for _, server := range g.servers {
		server.cancel()
	}
	var errs []error
	for _, server := range g.servers {
		if err := <-server.done; err != nil && !errors.Is(err, context.Canceled) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
