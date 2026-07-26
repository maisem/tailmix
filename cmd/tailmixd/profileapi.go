package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	tailmixprofile "github.com/maisem/tailmix/profile"
	"github.com/maisem/tailmix/profilesocket"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/safesocket"
	"tailscale.com/types/logid"
)

type profileAPIServer struct {
	cancel context.CancelFunc
	done   chan error
	path   string
	close  io.Closer
}

type profileAPIGroup struct {
	ctx     context.Context
	dir     string
	stderr  io.Writer
	mu      sync.Mutex
	servers map[string]profileAPIServer
	errs    chan error
}

func newProfileAPIGroup(ctx context.Context, dir string, stderr io.Writer) *profileAPIGroup {
	return &profileAPIGroup{
		ctx:     ctx,
		dir:     dir,
		stderr:  stderr,
		servers: map[string]profileAPIServer{},
		errs:    make(chan error, 64),
	}
}

func (g *profileAPIGroup) Errors() <-chan error { return g.errs }

func (g *profileAPIGroup) Start(rp runtimeProfile) error {
	provider, ok := rp.Engine.(tailmixprofile.LocalBackendProvider)
	if !ok {
		return fmt.Errorf("profile %q engine does not expose its LocalBackend", rp.State.ID)
	}
	backend, err := provider.LocalBackend()
	if err != nil {
		return fmt.Errorf("profile %q LocalBackend: %w", rp.State.ID, err)
	}
	path, err := profilesocket.Path(g.dir, rp.State.ID)
	if err != nil {
		return err
	}
	listener, err := safesocket.Listen(path)
	if err != nil {
		return fmt.Errorf("listen on profile %q LocalAPI socket %s: %w", rp.State.ID, path, err)
	}
	logf := prefixedLogf(g.stderr, rp.State.ID+"-api")
	server := ipnserver.New(logf, logid.PublicID{}, backend.EventBus(), backend.NetMon())
	server.SetLocalBackend(backend)
	serverCtx, cancel := context.WithCancel(g.ctx)
	done := make(chan error, 1)

	g.mu.Lock()
	if _, exists := g.servers[rp.State.ID]; exists {
		g.mu.Unlock()
		cancel()
		_ = listener.Close()
		return fmt.Errorf("profile %q LocalAPI is already running", rp.State.ID)
	}
	g.servers[rp.State.ID] = profileAPIServer{cancel: cancel, done: done, path: path, close: listener}
	g.mu.Unlock()

	fmt.Fprintf(g.stderr, "profile %s LocalAPI socket %s\n", rp.State.ID, path)
	go func(profileID string) {
		err := server.Run(serverCtx, listener)
		done <- err
		if err != nil && serverCtx.Err() == nil {
			select {
			case g.errs <- fmt.Errorf("serve profile %q LocalAPI: %w", profileID, err):
			case <-g.ctx.Done():
			}
		}
	}(rp.State.ID)
	return nil
}

func (g *profileAPIGroup) Stop(profileID string) error {
	g.mu.Lock()
	server, ok := g.servers[profileID]
	if ok {
		delete(g.servers, profileID)
	}
	g.mu.Unlock()
	if !ok {
		return nil
	}
	server.cancel()
	_ = server.close.Close()
	err := <-server.done
	removeErr := os.Remove(server.path)
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
		return errors.Join(err, removeErr)
	}
	return removeErr
}

func (g *profileAPIGroup) Close() error {
	g.mu.Lock()
	ids := make([]string, 0, len(g.servers))
	for profileID := range g.servers {
		ids = append(ids, profileID)
	}
	g.mu.Unlock()
	var errs []error
	for _, profileID := range ids {
		if err := g.Stop(profileID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
