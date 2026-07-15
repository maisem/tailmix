//go:build !darwin && !linux

package hosttun

import (
	"errors"
)

func Open(OpenConfig) (Host, error) {
	return nil, errors.New("tailmix host TUN mode is currently implemented only on Darwin and Linux")
}
