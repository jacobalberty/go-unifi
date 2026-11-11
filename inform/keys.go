package inform

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// NewKey returns a new random device key, for adopting a device or
// replacing its key.
func NewKey() []byte {
	k := make([]byte, KeySize)
	_, _ = rand.Read(k) // never fails
	return k
}

// FormatKey renders a key as devices and controllers store it: 32
// lower-case hex digits (the mgmt_cfg "authkey").
func FormatKey(k []byte) string { return hex.EncodeToString(k) }

// ParseKey reads a key in authkey form (32 hex digits, any case,
// surrounding space ignored), e.g. one extracted from another controller.
func ParseKey(s string) ([]byte, error) {
	k, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("inform: key is not hex: %w", err)
	}
	if len(k) != KeySize {
		return nil, ErrKeySize
	}
	return k, nil
}
