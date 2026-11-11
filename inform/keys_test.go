package inform

import (
	"bytes"
	"errors"
	"testing"
)

func TestKeys(t *testing.T) {
	a, b := NewKey(), NewKey()
	if len(a) != KeySize || bytes.Equal(a, b) {
		t.Fatalf("NewKey: %x %x", a, b)
	}
	s := FormatKey(captureKey)
	if s != "e2c930683af3945e4d0d58d37a78c2a6" {
		t.Fatalf("FormatKey = %s", s)
	}
	k, err := ParseKey(" E2C930683AF3945E4D0D58D37A78C2A6\n")
	if err != nil || !bytes.Equal(k, captureKey) {
		t.Fatalf("ParseKey = %x, %v", k, err)
	}
	if _, err := ParseKey("e2c930"); !errors.Is(err, ErrKeySize) {
		t.Errorf("short key: %v", err)
	}
	if _, err := ParseKey("zz"); err == nil {
		t.Error("non-hex key accepted")
	}
}
