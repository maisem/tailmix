package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/maisem/tailmix/controlapi"
	"github.com/maisem/tailmix/profilesocket"
	"tailscale.com/safesocket"
)

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
	if err := os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("secure daemon control socket %s: %w", path, err)
	}
	server := &controlServer{
		path:     path,
		listener: listener,
		http:     &http.Server{Handler: controlapi.Handler(backend)},
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
