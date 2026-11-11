package inform

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"testing"
)

var (
	captureKey, _ = hex.DecodeString("e2c930683af3945e4d0d58d37a78c2a6")
	testMAC       = net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
)

func readCapture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/aes_snappy.dat")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A packet captured from a real access point decodes.
func TestDecodeCapture(t *testing.T) {
	b := readCapture(t)
	p, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if p.MAC.String() != "f0:9f:c2:79:63:90" || p.Flags != FlagEncrypted|FlagSnappy || p.Version != 0 || p.DataVersion != 1 {
		t.Fatalf("header = %+v", p)
	}
	msg, err := p.Decode(captureKey)
	if err != nil {
		t.Fatal(err)
	}
	var in map[string]any
	if err := json.Unmarshal(msg, &in); err != nil {
		t.Fatal(err)
	}
	if in["mac"] != "f0:9f:c2:79:63:90" || in["model"] != "U7PG2" || in["version"] != "3.9.27.8537" {
		t.Fatalf("inform = %.200v", in)
	}

	// The wrong key is reported as such, not as garbage JSON.
	if _, err := p.Decode(DefaultKey()); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong key: %v", err)
	}

	// Re-encoding the packet's framing reproduces the capture exactly.
	again, err := p.MarshalBinary()
	if err != nil || !bytes.Equal(again, b) {
		t.Fatalf("MarshalBinary differs from capture (%v)", err)
	}
}

func TestRoundTrip(t *testing.T) {
	msg := []byte(`{"_type":"noop","interval":10}`)
	for _, f := range []Flags{
		0,
		FlagZlib,
		FlagSnappy,
		FlagEncrypted,
		FlagEncrypted | FlagZlib,
		FlagEncrypted | FlagSnappy,
		FlagEncrypted | FlagGCM,
		FlagEncrypted | FlagGCM | FlagZlib,
		FlagEncrypted | FlagGCM | FlagSnappy,
	} {
		t.Run(f.String(), func(t *testing.T) {
			p, err := Seal(testMAC, f, captureKey, msg)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := p.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if f&FlagEncrypted != 0 && bytes.Contains(wire, msg) {
				t.Fatal("plaintext visible in encrypted packet")
			}
			q, err := Parse(wire)
			if err != nil {
				t.Fatal(err)
			}
			got, err := q.Decode(captureKey)
			if err != nil || !bytes.Equal(got, msg) {
				t.Fatalf("decode = %q, %v", got, err)
			}
			if f&FlagGCM != 0 && len(q.Payload) < gcmTagSize {
				t.Fatal("GCM payload lacks its tag")
			}
		})
	}
}

// GCM authenticates the header as well as the payload.
func TestGCMTamper(t *testing.T) {
	p, err := Seal(testMAC, FlagEncrypted|FlagGCM|FlagZlib, captureKey, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := p.MarshalBinary()
	for name, i := range map[string]int{"mac": 9, "iv": 20, "payload": HeaderSize + 1, "tag": len(wire) - 1} {
		bad := bytes.Clone(wire)
		bad[i] ^= 0x01
		q, err := Parse(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := q.Decode(captureKey); !errors.Is(err, ErrDecrypt) {
			t.Errorf("tampered %s: %v", name, err)
		}
	}
}

// Every encrypted packet gets a fresh IV.
func TestFreshIV(t *testing.T) {
	a, _ := Seal(testMAC, FlagEncrypted|FlagZlib, captureKey, []byte(`{}`))
	b, _ := Seal(testMAC, FlagEncrypted|FlagZlib, captureKey, []byte(`{}`))
	if a.IV == b.IV || a.IV == [16]byte{} {
		t.Fatalf("IVs %x and %x", a.IV, b.IV)
	}
}

func TestSealDeterministic(t *testing.T) {
	iv := bytes.Repeat([]byte{7}, 16)
	p, err := seal(bytes.NewReader(iv), testMAC, FlagEncrypted, captureKey, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := p.MarshalBinary()
	// Header: magic, version 0, MAC, flags 1, IV, data version 1, length 16.
	want := "544e4255" + "00000000" + "deadbeef0001" + "0001" + hex.EncodeToString(iv) + "00000001" + "00000010"
	if got := hex.EncodeToString(wire[:HeaderSize]); got != want {
		t.Fatalf("header\n got %s\nwant %s", got, want)
	}
}

func TestParseErrors(t *testing.T) {
	good := readCapture(t)
	for name, b := range map[string][]byte{
		"empty":     nil,
		"short":     good[:39],
		"magic":     append([]byte("XXXX"), good[4:]...),
		"truncated": good[:len(good)-1],
		"trailing":  append(bytes.Clone(good), 0),
	} {
		if _, err := Parse(b); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDecodeErrors(t *testing.T) {
	if _, err := Seal(testMAC, FlagEncrypted, []byte("short"), []byte(`{}`)); !errors.Is(err, ErrKeySize) {
		t.Errorf("short key: %v", err)
	}
	if _, err := Seal(testMAC, FlagGCM, captureKey, []byte(`{}`)); !errors.Is(err, ErrMalformed) {
		t.Errorf("GCM without encryption: %v", err)
	}
	if _, err := Seal(testMAC, FlagZlib|FlagSnappy, nil, []byte(`{}`)); !errors.Is(err, ErrMalformed) {
		t.Errorf("both compressions: %v", err)
	}
	if _, err := Seal(testMAC, FlagEncrypted, captureKey, make([]byte, maxMessage+1)); !errors.Is(err, ErrMalformed) {
		t.Errorf("oversized message: %v", err)
	}
	if _, err := Seal(net.HardwareAddr{1, 2}, 0, nil, []byte(`{}`)); err != nil {
		t.Errorf("seal itself should not check the MAC: %v", err)
	}
	p := &Packet{MAC: net.HardwareAddr{1, 2}}
	if _, err := p.MarshalBinary(); !errors.Is(err, ErrMalformed) {
		t.Errorf("short MAC: %v", err)
	}
	// Garbage that decrypts to bad padding or bad compression.
	p = &Packet{MAC: testMAC, Flags: FlagEncrypted, Payload: bytes.Repeat([]byte{1}, 32)}
	if _, err := p.Decode(captureKey); !errors.Is(err, ErrDecrypt) {
		t.Errorf("garbage CBC: %v", err)
	}
	p = &Packet{MAC: testMAC, Flags: FlagSnappy, Payload: []byte{0xff, 0xff, 0xff, 0xff, 0x0f}}
	if _, err := p.Decode(nil); !errors.Is(err, ErrMalformed) {
		t.Errorf("oversized snappy: %v", err)
	}
}

func TestFlagsString(t *testing.T) {
	for f, want := range map[Flags]string{0: "none", FlagEncrypted | FlagSnappy: "encrypted|snappy", 0x30: "0x30"} {
		if got := f.String(); got != want {
			t.Errorf("%d: %q, want %q", f, got, want)
		}
	}
}

func FuzzParseDecode(f *testing.F) {
	// Small seeds keep the fuzzer fast; the capture is covered by
	// TestDecodeCapture.
	for _, flags := range []Flags{FlagEncrypted | FlagZlib, FlagEncrypted | FlagSnappy, FlagEncrypted | FlagGCM | FlagZlib} {
		p, err := Seal(testMAC, flags, captureKey, []byte(`{"mac":"de:ad:be:ef:00:01"}`))
		if err != nil {
			f.Fatal(err)
		}
		b, _ := p.MarshalBinary()
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Parse(b)
		if err != nil {
			return
		}
		_, _ = p.Decode(captureKey)
		if out, err := p.MarshalBinary(); err == nil && !bytes.Equal(out, b) {
			t.Fatal("parse/marshal is not lossless")
		}
	})
}
