package inform

import (
	"context"
	"errors"
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

// Handler serves POST /inform. It parses and decrypts each packet, passes
// the message to Serve, and encodes the reply with the same key and flags
// the device used.
type Handler struct {
	// Key returns the AES key for a device: its own key once adopted,
	// DefaultKey() before that. Returning ErrUnknownDevice answers 404.
	Key func(ctx context.Context, mac net.HardwareAddr) ([]byte, error)
	// Serve handles a decoded inform. Returning ErrUnknownDevice answers
	// 404, e.g. for a device that is waiting to be adopted.
	Serve func(ctx context.Context, p *Packet, in *Inform) (Response, error)
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
	key, err := h.Key(ctx, p.MAC)
	if err != nil {
		h.fail(ctx, w, p.MAC, statusOf(err), err)
		return
	}
	msg, err := p.Decode(key)
	if err != nil {
		h.fail(ctx, w, p.MAC, http.StatusBadRequest, err)
		return
	}
	in, err := ParseInform(msg)
	if err != nil {
		h.fail(ctx, w, p.MAC, http.StatusBadRequest, err)
		return
	}
	resp, err := h.Serve(ctx, p, in)
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
	out, err := Seal(p.MAC, p.Flags, key, reply)
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
