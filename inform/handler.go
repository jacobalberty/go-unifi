package inform

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// ErrUnknownDevice tells Handler to answer 404, which is how a controller
// tells a device it is not (or no longer) managed here.
var ErrUnknownDevice = errors.New("inform: unknown device")

// MaxPacketSize bounds the request bodies Handler accepts.
const MaxPacketSize = 1 << 20

// Key is a candidate AES key for a device. Name is the caller's label for
// where the key comes from (e.g. "current", "pending", "imported",
// "default"); Handler reports which candidate worked.
type Key struct {
	Name  string
	Bytes []byte
}

// Handler serves POST /inform. It parses each packet, decrypts it with the
// first of the device's candidate keys that works, passes the message to
// Serve, and seals the reply with that key and the flags the device used.
//
// Trying several keys lets a controller change a device's key safely: while
// a new key is on its way (in a SetParam reply the device may not have
// received), offer both the new and the old key, and treat the device as
// switched once Serve sees the new one used.
type Handler struct {
	// Keys returns the device's candidate keys, tried in order: typically
	// its pending and current keys, then DefaultKey() for devices that are
	// not adopted yet. Returning ErrUnknownDevice answers 404.
	Keys func(ctx context.Context, mac net.HardwareAddr) ([]Key, error)
	// Serve handles a decoded inform. used is the candidate that decrypted
	// it (the zero Key for an unencrypted packet). Returning
	// ErrUnknownDevice answers 404, e.g. for a device waiting to be adopted.
	Serve func(ctx context.Context, p *Packet, in *Inform, used Key) (Response, error)
	// OnError, if set, is told why a request failed (for logging). mac is
	// nil when the packet could not be parsed.
	OnError func(ctx context.Context, mac net.HardwareAddr, status int, err error)
	// Now replaces time.Now for the server time in replies.
	Now func() time.Time
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.fail(ctx, w, nil, http.StatusMethodNotAllowed, errors.New("inform: method not allowed"))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxPacketSize))
	if err != nil {
		h.fail(ctx, w, nil, http.StatusRequestEntityTooLarge, err)
		return
	}
	p, err := Parse(body)
	if err != nil {
		h.fail(ctx, w, nil, http.StatusBadRequest, err)
		return
	}
	keys, err := h.Keys(ctx, p.MAC)
	if err != nil {
		h.fail(ctx, w, p.MAC, statusOf(err), err)
		return
	}
	used, in, err := open(p, keys)
	if errors.Is(err, ErrDecrypt) {
		// No key fits: the device belongs to another controller, or we hold
		// the wrong key. 404 keeps it waiting.
		h.fail(ctx, w, p.MAC, http.StatusNotFound, err)
		return
	}
	if err != nil {
		h.fail(ctx, w, p.MAC, http.StatusBadRequest, err)
		return
	}
	resp, err := h.Serve(ctx, p, in, used)
	if err != nil {
		h.fail(ctx, w, p.MAC, statusOf(err), err)
		return
	}
	now := time.Now
	if h.Now != nil {
		now = h.Now
	}
	reply, err := MarshalResponse(resp, now())
	if err != nil {
		h.fail(ctx, w, p.MAC, http.StatusInternalServerError, err)
		return
	}
	out, err := Seal(p.MAC, p.Flags, used.Bytes, reply)
	if err == nil {
		reply, err = out.MarshalBinary()
	}
	if err != nil {
		h.fail(ctx, w, p.MAC, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-binary")
	_, _ = w.Write(reply)
}

// open decodes p with the first candidate key that yields a valid inform. A
// key only counts once the message also decompresses and parses.
func open(p *Packet, keys []Key) (Key, *Inform, error) {
	if p.Flags&FlagEncrypted == 0 {
		msg, err := p.Decode(nil)
		if err != nil {
			return Key{}, nil, err
		}
		in, err := ParseInform(msg)
		return Key{}, in, err
	}
	// With a wrong CBC key, padding is valid about 1 time in 256 and the
	// failure shows up in decompression or JSON instead, so every failure
	// here means "not this key".
	var last error
	for _, k := range keys {
		msg, err := p.Decode(k.Bytes)
		if err != nil {
			last = err
			continue
		}
		in, err := ParseInform(msg)
		if err != nil {
			last = err
			continue
		}
		return k, in, nil
	}
	if last == nil {
		return Key{}, nil, fmt.Errorf("%w: no candidate keys", ErrDecrypt)
	}
	return Key{}, nil, fmt.Errorf("%w: no candidate key opened the packet (last error: %v)", ErrDecrypt, last)
}

func statusOf(err error) int {
	if errors.Is(err, ErrUnknownDevice) {
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}

func (h *Handler) fail(ctx context.Context, w http.ResponseWriter, mac net.HardwareAddr, status int, err error) {
	if h.OnError != nil {
		h.OnError(ctx, mac, status, err)
	}
	http.Error(w, http.StatusText(status), status)
}
