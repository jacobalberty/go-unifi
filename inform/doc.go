// Package inform implements the UniFi inform protocol: the packets UniFi
// devices POST to a controller's /inform endpoint and the replies they
// expect.
//
// A packet is a 40-byte header followed by a payload that is optionally
// compressed (zlib or snappy) and then optionally encrypted (AES-128-CBC
// with PKCS#7 padding, or AES-128-GCM). Devices that have not been adopted
// use DefaultKey; adoption hands each device its own key (the "authkey" in
// mgmt_cfg).
//
//	offset size field
//	0      4    magic "TNBU"
//	4      4    packet version (0)
//	8      6    device MAC address
//	14     2    flags (see Flags)
//	16     16   AES IV (CBC) or nonce (GCM)
//	32     4    data version (1)
//	36     4    payload length
//	40     n    payload
//
// For GCM the 40-byte header is the additional authenticated data and the
// 16-byte authentication tag ends the payload.
//
// The package does no logging and has no telemetry. Functions take a
// context where they call out and report problems as errors.
package inform
