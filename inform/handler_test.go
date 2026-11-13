package inform

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// device simulates a UniFi device: it seals informs with its current key
// and reads replies with it.
type device struct {
	t     *testing.T
	mac   net.HardwareAddr
	key   []byte
	flags Flags
}

func (d *device) inform(h http.Handler) (*httptest.ResponseRecorder, []byte) {
	d.t.Helper()
	p, err := Seal(d.mac, d.flags, d.key, []byte(`{"model":"U6-Lite","default":false}`))
	if err != nil {
		d.t.Fatal(err)
	}
	b, _ := p.MarshalBinary()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/inform", bytes.NewReader(b)))
	if rec.Code != http.StatusOK {
		return rec, nil
	}
	reply, err := Parse(rec.Body.Bytes())
	if err != nil || reply.Flags != d.flags&^(FlagZlib|FlagSnappy) || !bytes.Equal(reply.MAC, d.mac) {
		d.t.Fatalf("reply %+v, %v", reply, err)
	}
	msg, err := reply.Decode(d.key)
	if err != nil {
		d.t.Fatalf("device cannot read the reply with its own key: %v", err)
	}
	return rec, msg
}

func TestHandlerReplies(t *testing.T) {
	adopted := &device{t: t, mac: net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x02}, key: captureKey}
	h := &Handler{
		Keys: func(context.Context, net.HardwareAddr) ([]Key, error) {
			return []Key{{"current", captureKey}, {"default", DefaultKey()}}, nil
		},
		Serve: func(_ context.Context, p *Packet, in *Inform, used Key) (Response, error) {
			if used.Name != "current" || in.Model != "U6-Lite" {
				return nil, ErrUnknownDevice
			}
			return Noop{Interval: 30}, nil
		},
		Now: func() time.Time { return time.UnixMilli(42) },
	}
	for _, flags := range []Flags{FlagEncrypted | FlagSnappy, FlagEncrypted | FlagGCM | FlagZlib} {
		adopted.flags = flags
		if _, msg := adopted.inform(h); string(msg) != `{"_type":"noop","interval":30,"server_time_in_utc":"42"}` {
			t.Fatalf("%s: reply %s", flags, msg)
		}
	}
}

// Adoption with a lost reply: the controller offers the new key and the old
// one until the device proves it switched.
func TestHandlerKeySwitch(t *testing.T) {
	d := &device{t: t, mac: net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x03}, key: DefaultKey(), flags: FlagEncrypted | FlagSnappy}
	newKey := NewKey()
	var current []byte // nil until the device is seen using newKey
	var seen []string
	h := &Handler{
		Keys: func(context.Context, net.HardwareAddr) ([]Key, error) {
			if current != nil {
				return []Key{{"current", current}}, nil
			}
			return []Key{{"pending", newKey}, {"default", DefaultKey()}}, nil
		},
		Serve: func(_ context.Context, _ *Packet, _ *Inform, used Key) (Response, error) {
			seen = append(seen, used.Name)
			if used.Name == "pending" {
				current = newKey // the device switched: commit
				return Noop{Interval: 10}, nil
			}
			cfg, err := MgmtConfig{AuthKey: newKey, CfgVersion: "1"}.Config()
			if err != nil {
				return nil, err
			}
			return SetParam{ManagementConfig: cfg.String()}, nil
		},
	}

	// 1. The device informs with the default key and gets the new key,
	//    sealed with the key it can read.
	_, msg := d.inform(h)
	if !bytes.Contains(msg, []byte(`"_type":"setparam"`)) || !bytes.Contains(msg, []byte(FormatKey(newKey))) {
		t.Fatalf("adoption reply %s", msg)
	}
	// 2. The reply is lost; the device informs with the default key again
	//    and is still understood.
	if rec, _ := d.inform(h); rec.Code != http.StatusOK {
		t.Fatalf("retry after lost reply: %d", rec.Code)
	}
	// 3. The device applies the new key; the controller commits it.
	d.key = newKey
	if _, msg := d.inform(h); !bytes.Contains(msg, []byte(`"_type":"noop"`)) {
		t.Fatalf("after switch %s", msg)
	}
	// 4. The old key no longer works.
	d.key = DefaultKey()
	if rec, _ := d.inform(h); rec.Code != http.StatusNotFound {
		t.Fatalf("old key after commit: %d", rec.Code)
	}
	if want := []string{"default", "default", "pending"}; len(seen) != 3 || seen[0] != want[0] || seen[1] != want[1] || seen[2] != want[2] {
		t.Fatalf("keys used %v, want %v", seen, want)
	}
}

func TestHandlerErrors(t *testing.T) {
	var failures []int
	h := &Handler{
		Keys: func(_ context.Context, mac net.HardwareAddr) ([]Key, error) {
			if mac[5] == 0xff {
				return nil, ErrUnknownDevice
			}
			return []Key{{"default", DefaultKey()}}, nil
		},
		Serve: func(context.Context, *Packet, *Inform, Key) (Response, error) {
			return nil, ErrUnknownDevice // pending adoption
		},
		OnError: func(_ context.Context, _ net.HardwareAddr, status int, _ error) { failures = append(failures, status) },
	}
	post := func(body []byte) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/inform", bytes.NewReader(body)))
		return rec.Code
	}
	seal := func(mac net.HardwareAddr, flags Flags, key, msg []byte) []byte {
		p, err := Seal(mac, flags, key, msg)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := p.MarshalBinary()
		return b
	}
	for name, tc := range map[string]struct {
		body []byte
		want int
	}{
		"pending device": {seal(testMAC, FlagEncrypted|FlagZlib, DefaultKey(), []byte(`{}`)), http.StatusNotFound},
		"foreign key":    {seal(testMAC, FlagEncrypted|FlagZlib, captureKey, []byte(`{}`)), http.StatusNotFound},
		"Keys says no":   {seal(net.HardwareAddr{1, 2, 3, 4, 5, 0xff}, FlagEncrypted, DefaultKey(), []byte(`{}`)), http.StatusNotFound},
		"plain bad JSON": {seal(testMAC, 0, nil, []byte(`nope`)), http.StatusBadRequest},
		"not a packet":   {[]byte("junk"), http.StatusBadRequest},
	} {
		failures = nil
		if got := post(tc.body); got != tc.want || len(failures) != 1 || failures[0] != tc.want {
			t.Errorf("%s: status %d (OnError %v), want %d", name, got, failures, tc.want)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/inform", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", rec.Code)
	}
	if _, _, err := open(&Packet{Flags: FlagEncrypted}, nil); !errors.Is(err, ErrDecrypt) {
		t.Errorf("no keys: %v", err)
	}
}

// A wrong CBC key yields valid padding about 1 time in 256; that must still
// read as "wrong key", never as a malformed packet.
func TestOpenWrongKeyIsAlwaysErrDecrypt(t *testing.T) {
	keys := []Key{{"default", DefaultKey()}}
	for i := range 3000 {
		flags := []Flags{FlagEncrypted | FlagZlib, FlagEncrypted | FlagSnappy, FlagEncrypted}[i%3]
		p, err := Seal(testMAC, flags, captureKey, []byte(`{"model":"x"}`))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := open(p, keys); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("iteration %d (%s): %v", i, flags, err)
		}
	}
}

// Devices set up for another controller are reported, with their MAC,
// even though nothing can decrypt them.
func TestHandlerUndecryptable(t *testing.T) {
	var reported []string
	h := &Handler{
		Keys: func(context.Context, net.HardwareAddr) ([]Key, error) {
			return []Key{{"default", DefaultKey()}}, nil
		},
		Serve: func(context.Context, *Packet, *Inform, Key) (Response, error) {
			return nil, ErrUnknownDevice
		},
		Undecryptable: func(_ context.Context, p *Packet) { reported = append(reported, p.MAC.String()) },
	}
	foreign := &device{t: t, mac: net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x04}, key: captureKey, flags: FlagEncrypted | FlagGCM | FlagSnappy}
	if rec, _ := foreign.inform(h); rec.Code != http.StatusNotFound {
		t.Fatalf("foreign device: %d", rec.Code)
	}
	pending := &device{t: t, mac: net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x05}, key: DefaultKey(), flags: FlagEncrypted | FlagZlib}
	if rec, _ := pending.inform(h); rec.Code != http.StatusNotFound {
		t.Fatalf("pending device: %d", rec.Code)
	}
	if len(reported) != 1 || reported[0] != "de:ad:be:ef:00:04" {
		t.Fatalf("reported %v, want only the foreign device", reported)
	}
}
