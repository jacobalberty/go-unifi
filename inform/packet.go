package inform

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/golang/snappy"
)

// Magic starts every inform packet ("TNBU", "UBNT" reversed).
const Magic uint32 = 0x544e4255

// HeaderSize is the length of the fixed packet header.
const HeaderSize = 40

// KeySize is the AES key length devices use (AES-128).
const KeySize = 16

const (
	packetVersion = 0
	dataVersion   = 1
	ivSize        = 16
	gcmTagSize    = 16
)

// Flags describe how a payload is encoded.
type Flags uint16

const (
	FlagEncrypted Flags = 1 << iota // AES; CBC unless FlagGCM
	FlagZlib                        // zlib compressed
	FlagSnappy                      // snappy compressed (block format)
	FlagGCM                         // AES-GCM instead of CBC
)

func (f Flags) String() string {
	var parts []string
	for _, n := range []struct {
		f    Flags
		name string
	}{{FlagEncrypted, "encrypted"}, {FlagZlib, "zlib"}, {FlagSnappy, "snappy"}, {FlagGCM, "gcm"}} {
		if f&n.f != 0 {
			parts = append(parts, n.name)
			f &^= n.f
		}
	}
	if f != 0 {
		parts = append(parts, fmt.Sprintf("0x%x", uint16(f)))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "|")
}

// DefaultKey returns the key unadopted devices use: MD5("ubnt").
func DefaultKey() []byte {
	return []byte{0xba, 0x86, 0xf2, 0xbb, 0xe1, 0x07, 0xc7, 0xc5, 0x7e, 0xb5, 0xf2, 0x69, 0x07, 0x75, 0xc7, 0x12}
}

var (
	// ErrMalformed is returned for bytes that are not a valid inform packet.
	ErrMalformed = errors.New("inform: malformed packet")
	// ErrDecrypt is returned when a payload cannot be decrypted, usually
	// because the key is wrong.
	ErrDecrypt = errors.New("inform: cannot decrypt payload (wrong key?)")
	// ErrKeySize is returned for keys that are not KeySize bytes.
	ErrKeySize = errors.New("inform: key must be 16 bytes")
)

// Packet is an inform packet. Payload is as on the wire: compressed and/or
// encrypted according to Flags, including the GCM tag.
type Packet struct {
	Version     uint32
	MAC         net.HardwareAddr
	Flags       Flags
	IV          [ivSize]byte
	DataVersion uint32
	Payload     []byte
}

// Parse decodes a packet's framing. It does not decrypt the payload; see
// Packet.Decode.
func Parse(b []byte) (*Packet, error) {
	if len(b) < HeaderSize {
		return nil, fmt.Errorf("%w: %d bytes is shorter than the %d-byte header", ErrMalformed, len(b), HeaderSize)
	}
	if m := binary.BigEndian.Uint32(b[0:4]); m != Magic {
		return nil, fmt.Errorf("%w: bad magic 0x%08x", ErrMalformed, m)
	}
	n := binary.BigEndian.Uint32(b[36:40])
	if uint64(n) != uint64(len(b)-HeaderSize) {
		return nil, fmt.Errorf("%w: header says %d payload bytes, packet has %d", ErrMalformed, n, len(b)-HeaderSize)
	}
	p := &Packet{
		Version:     binary.BigEndian.Uint32(b[4:8]),
		MAC:         net.HardwareAddr(bytes.Clone(b[8:14])),
		Flags:       Flags(binary.BigEndian.Uint16(b[14:16])),
		DataVersion: binary.BigEndian.Uint32(b[32:36]),
		Payload:     bytes.Clone(b[HeaderSize:]),
	}
	copy(p.IV[:], b[16:32])
	return p, nil
}

// header returns the 40-byte header for a payload of length n.
func (p *Packet) header(n int) ([]byte, error) {
	if len(p.MAC) != 6 {
		return nil, fmt.Errorf("%w: MAC must be 6 bytes, got %d", ErrMalformed, len(p.MAC))
	}
	if uint64(n) > 1<<31 {
		return nil, fmt.Errorf("%w: payload too large", ErrMalformed)
	}
	h := make([]byte, HeaderSize)
	binary.BigEndian.PutUint32(h[0:4], Magic)
	binary.BigEndian.PutUint32(h[4:8], p.Version)
	copy(h[8:14], p.MAC)
	binary.BigEndian.PutUint16(h[14:16], uint16(p.Flags))
	copy(h[16:32], p.IV[:])
	binary.BigEndian.PutUint32(h[32:36], p.DataVersion)
	binary.BigEndian.PutUint32(h[36:40], uint32(n)) //nolint:gosec // bounded above
	return h, nil
}

// MarshalBinary returns the packet in wire format.
func (p *Packet) MarshalBinary() ([]byte, error) {
	h, err := p.header(len(p.Payload))
	if err != nil {
		return nil, err
	}
	return append(h, p.Payload...), nil
}

// Decode decrypts (when FlagEncrypted is set) and decompresses the payload,
// returning the JSON message. key is ignored for unencrypted packets.
func (p *Packet) Decode(key []byte) ([]byte, error) {
	data := p.Payload
	if p.Flags&FlagEncrypted != 0 {
		var err error
		if p.Flags&FlagGCM != 0 {
			data, err = p.openGCM(key)
		} else {
			data, err = openCBC(key, p.IV[:], data)
		}
		if err != nil {
			return nil, err
		}
	}
	return decompress(p.Flags, data)
}

// Seal builds an encoded packet for mac carrying the JSON message msg:
// compressed and encrypted with key according to flags, with a fresh random
// IV. Version and DataVersion take the standard values (0 and 1).
func Seal(mac net.HardwareAddr, flags Flags, key, msg []byte) (*Packet, error) {
	return seal(rand.Reader, mac, flags, key, msg)
}

func seal(random io.Reader, mac net.HardwareAddr, flags Flags, key, msg []byte) (*Packet, error) {
	p := &Packet{Version: packetVersion, MAC: bytes.Clone(mac), Flags: flags, DataVersion: dataVersion}
	if flags&FlagGCM != 0 && flags&FlagEncrypted == 0 {
		return nil, fmt.Errorf("%w: FlagGCM needs FlagEncrypted", ErrMalformed)
	}
	if len(msg) > maxMessage {
		return nil, fmt.Errorf("%w: message larger than %d bytes", ErrMalformed, maxMessage)
	}
	data, err := compress(flags, msg)
	if err != nil {
		return nil, err
	}
	if flags&FlagEncrypted == 0 {
		p.Payload = data
		return p, nil
	}
	if _, err := io.ReadFull(random, p.IV[:]); err != nil {
		return nil, fmt.Errorf("inform: generating IV: %w", err)
	}
	if flags&FlagGCM != 0 {
		err = p.sealGCM(key, data)
	} else {
		p.Payload, err = sealCBC(key, p.IV[:], data)
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

func newCipher(key []byte) (cipher.Block, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	return aes.NewCipher(key)
}

func openCBC(key, iv, data []byte) ([]byte, error) {
	block, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%w: CBC payload is not a whole number of blocks", ErrDecrypt)
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	return pkcs7Unpad(out)
}

func sealCBC(key, iv, data []byte) ([]byte, error) {
	block, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	// Bound the size so padding cannot overflow (the header caps payloads
	// at 1<<31 bytes anyway).
	if len(data) > 1<<31-aes.BlockSize {
		return nil, fmt.Errorf("%w: payload too large", ErrMalformed)
	}
	padded := pkcs7Pad(data, aes.BlockSize)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(padded, padded)
	return padded, nil
}

func (p *Packet) openGCM(key []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	aad, err := p.header(len(p.Payload))
	if err != nil {
		return nil, err
	}
	out, err := gcm.Open(nil, p.IV[:], p.Payload, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	return out, nil
}

func (p *Packet) sealGCM(key, data []byte) error {
	gcm, err := newGCM(key)
	if err != nil {
		return err
	}
	// The header (with the final length, tag included) is authenticated.
	aad, err := p.header(len(data) + gcmTagSize)
	if err != nil {
		return err
	}
	p.Payload = gcm.Seal(nil, p.IV[:], data, aad)
	return nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithNonceSize(block, ivSize)
}

func pkcs7Pad(b []byte, size int) []byte {
	n := size - len(b)%size
	out := make([]byte, len(b), len(b)+n)
	copy(out, b)
	return append(out, bytes.Repeat([]byte{byte(n)}, n)...)
}

func pkcs7Unpad(b []byte) ([]byte, error) {
	n := int(b[len(b)-1])
	if n == 0 || n > aes.BlockSize || n > len(b) {
		return nil, fmt.Errorf("%w: bad padding", ErrDecrypt)
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return nil, fmt.Errorf("%w: bad padding", ErrDecrypt)
		}
	}
	return b[:len(b)-n], nil
}

// maxMessage bounds decompressed messages (real informs are a few KiB).
const maxMessage = 8 << 20

func compress(f Flags, msg []byte) ([]byte, error) {
	switch {
	case f&FlagZlib != 0 && f&FlagSnappy != 0:
		return nil, fmt.Errorf("%w: both zlib and snappy flags set", ErrMalformed)
	case f&FlagZlib != 0:
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		if _, err := w.Write(msg); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		return b.Bytes(), nil
	case f&FlagSnappy != 0:
		return snappy.Encode(nil, msg), nil
	}
	return bytes.Clone(msg), nil
}

func decompress(f Flags, data []byte) ([]byte, error) {
	switch {
	case f&FlagZlib != 0 && f&FlagSnappy != 0:
		return nil, fmt.Errorf("%w: both zlib and snappy flags set", ErrMalformed)
	case f&FlagZlib != 0:
		r, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("%w: zlib: %v", ErrMalformed, err)
		}
		defer func() { _ = r.Close() }()
		out, err := io.ReadAll(io.LimitReader(r, maxMessage+1))
		if err != nil {
			return nil, fmt.Errorf("%w: zlib: %v", ErrMalformed, err)
		}
		if len(out) > maxMessage {
			return nil, fmt.Errorf("%w: message larger than %d bytes", ErrMalformed, maxMessage)
		}
		return out, nil
	case f&FlagSnappy != 0:
		n, err := snappy.DecodedLen(data)
		if err != nil || n > maxMessage {
			return nil, fmt.Errorf("%w: snappy: bad or oversized block", ErrMalformed)
		}
		out, err := snappy.Decode(nil, data)
		if err != nil {
			return nil, fmt.Errorf("%w: snappy: %v", ErrMalformed, err)
		}
		return out, nil
	}
	return data, nil
}
