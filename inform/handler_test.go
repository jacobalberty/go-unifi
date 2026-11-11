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

func TestHandler(t *testing.T) {
	adopted := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x02}
	var failures []int
	h := &Handler{
		Key: func(_ context.Context, mac net.HardwareAddr) ([]byte, error) {
			if bytes.Equal(mac, adopted) {
				return captureKey, nil
			}
			return DefaultKey(), nil
		},
		Serve: func(_ context.Context, p *Packet, in *Inform) (Response, error) {
			if !bytes.Equal(p.MAC, adopted) {
				return nil, ErrUnknownDevice // pending adoption
			}
			if in.Model != "U6-Lite" {
				return nil, errors.New("unexpected model")
			}
			return Noop{Interval: 30}, nil
		},
		OnError: func(_ context.Context, _ net.HardwareAddr, status int, _ error) { failures = append(failures, status) },
		Now:     func() time.Time { return time.UnixMilli(42) },
	}
	post := func(body []byte) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/inform", bytes.NewReader(body)))
		return rec
	}
	packet := func(mac net.HardwareAddr, flags Flags, key []byte) []byte {
		p, err := Seal(mac, flags, key, []byte(`{"model":"U6-Lite"}`))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := p.MarshalBinary()
		return b
	}

	// An adopted device gets a reply sealed with its key and its flags.
	for _, flags := range []Flags{FlagEncrypted | FlagSnappy, FlagEncrypted | FlagGCM | FlagZlib} {
		rec := post(packet(adopted, flags, captureKey))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", flags, rec.Code)
		}
		p, err := Parse(rec.Body.Bytes())
		if err != nil || p.Flags != flags || !bytes.Equal(p.MAC, adopted) {
			t.Fatalf("%s: reply %+v, %v", flags, p, err)
		}
		msg, err := p.Decode(captureKey)
		if err != nil || string(msg) != `{"_type":"noop","interval":30,"server_time_in_utc":"42"}` {
			t.Fatalf("%s: reply %s, %v", flags, msg, err)
		}
	}

	failures = nil
	if rec := post(packet(testMAC, FlagEncrypted|FlagZlib, DefaultKey())); rec.Code != http.StatusNotFound {
		t.Errorf("pending device: %d", rec.Code)
	}
	if rec := post(packet(adopted, FlagEncrypted|FlagZlib, DefaultKey())); rec.Code != http.StatusBadRequest {
		t.Errorf("wrong key: %d", rec.Code)
	}
	if rec := post([]byte("junk")); rec.Code != http.StatusBadRequest {
		t.Errorf("junk: %d", rec.Code)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/inform", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", rec.Code)
	}
	if want := []int{404, 400, 400, 405}; len(failures) != len(want) {
		t.Errorf("OnError saw %v, want %v", failures, want)
	}
}
