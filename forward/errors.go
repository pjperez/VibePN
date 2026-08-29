package forward

import (
	"errors"
)

var (
	errNetworkName        = errors.New("network name must be 1-255 bytes")
	errPacketTooLarge     = errors.New("packet too large")
	errInvalidNetworkName = errors.New("invalid network name length")
	errInvalidPacketLen   = errors.New("invalid packet length")
)
