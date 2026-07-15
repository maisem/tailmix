package socksproxy

import (
	"context"
	"errors"
	"net"

	"tailscale.com/net/socks5"
	"tailscale.com/types/logger"
)

func Serve(ctx context.Context, ln net.Listener, router *Router, logf logger.Logf) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	srv := &socks5.Server{
		Logf:   logf,
		Dialer: router.Dial,
	}
	err := srv.Serve(ln)
	if errors.Is(err, net.ErrClosed) && ctx.Err() != nil {
		return nil
	}
	return err
}
