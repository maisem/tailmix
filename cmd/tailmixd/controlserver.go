package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/maisem/tailmix/controlapi"
	"github.com/maisem/tailmix/profilesocket"
	"github.com/tailscale/peercred"
	"tailscale.com/safesocket"
)

type peerUIDContextKey struct{}

type controlServer struct {
	path      string
	listener  net.Listener
	http      *http.Server
	done      chan error
	closeOnce sync.Once
	closeErr  error
}

func startControlServer(ctx context.Context, socketDir string, backend controlapi.Backend) (*controlServer, error) {
	path := profilesocket.ControlPath(socketDir)
	listener, err := safesocket.Listen(path)
	if err != nil {
		return nil, fmt.Errorf("listen on daemon control socket %s: %w", path, err)
	}
	mode := os.FileMode(0600)
	if safesocket.PlatformUsesPeerCreds() {
		mode = 0666
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("secure daemon control socket %s: %w", path, err)
	}
	handler := controlapi.Handler(backend)
	httpServer := &http.Server{Handler: handler}
	if safesocket.PlatformUsesPeerCreds() {
		httpServer.Handler = requireRootForMutations(handler)
		httpServer.ConnContext = controlConnContext
	}
	server := &controlServer{
		path:     path,
		listener: listener,
		http:     httpServer,
		done:     make(chan error, 1),
	}
	go func() {
		err := server.http.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			err = nil
		}
		server.done <- err
	}()
	go func() {
		<-ctx.Done()
		_ = server.Close()
	}()
	return server, nil
}

func controlConnContext(ctx context.Context, conn net.Conn) context.Context {
	creds, err := peercred.Get(conn)
	if err != nil {
		return ctx
	}
	uid, ok := creds.UserID()
	if !ok {
		return ctx
	}
	return context.WithValue(ctx, peerUIDContextKey{}, uid)
}

func requireRootForMutations(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			next.ServeHTTP(w, r)
			return
		}
		uid, _ := r.Context().Value(peerUIDContextKey{}).(string)
		if uid != "0" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(controlapi.NewError(
				"permission_denied", "tailmix management commands require root"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *controlServer) Errors() <-chan error { return s.done }

func (s *controlServer) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = errors.Join(s.http.Close(), s.listener.Close())
		if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			s.closeErr = errors.Join(s.closeErr, err)
		}
	})
	return s.closeErr
}
