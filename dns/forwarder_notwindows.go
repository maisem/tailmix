//go:build !windows

package dns

import "syscall"

const errAddrInUse = syscall.EADDRINUSE
