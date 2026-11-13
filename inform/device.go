package inform

import (
	"encoding/json"
	"strconv"
	"strings"
)

// DeviceKind is the product line of a UniFi device.
type DeviceKind string

const (
	// KindUnknown is a device whose model this package does not recognise.
	KindUnknown     DeviceKind = ""
	KindAccessPoint DeviceKind = "access_point"
	KindSwitch      DeviceKind = "switch"
	KindGateway     DeviceKind = "gateway"
)

// Classify says what kind of device sent the inform and how many ports
// beyond its uplink it has, which is what a controller needs to decide
// whether port settings apply to it.
//
// An inform carries no device type, so the kind comes from the model code,
// whose prefix names the product line: U7PG2, U6-LR and UAP-AC-Pro are
// access points; US8P150 and USW-24-POE are switches; UDM-Pro and UXG are
// gateways. A model that matches nothing is KindUnknown with no ports.
//
// Most access points have no port of their own, so they report 0. The
// exception is the in-wall models, whose model code or display name
// ("AC IW") contains "IW": they have two LAN ports (checked on a
// UAP-AC-IW; other in-wall models may differ). A switch reports the length
// of the port_table of its inform when it sends one, else the number in its
// model code (US8P150 is 8, USM8P is 8, USW-24-POE is 24, USMINI is 0). Gateways report
// 0: their ports are not described by the model code.
func (in *Inform) Classify() (DeviceKind, int) {
	model := strings.ToUpper(in.Model)
	switch {
	case hasAnyPrefix(model, "UGW", "UDM", "UDR", "UXG", "UCG", "UDW"):
		return KindGateway, 0
	case hasAnyPrefix(model, "U7", "U6", "U5", "U2", "UAP", "UAL", "UHD", "UFL", "UBB", "BZ2", "UWB", "E7", "UK"):
		if strings.Contains(model, "IW") || strings.Contains(strings.ToUpper(in.ModelDisplay), "IW") {
			return KindAccessPoint, 2
		}
		return KindAccessPoint, 0
	case strings.HasPrefix(model, "US"):
		if n := portTableLen(in.Raw); n > 0 {
			return KindSwitch, n
		}
		return KindSwitch, switchPortsFromModel(model)
	}
	return KindUnknown, 0
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// portTableLen is the number of entries of the inform's port_table, or 0.
func portTableLen(raw json.RawMessage) int {
	var v struct {
		PortTable []json.RawMessage `json:"port_table"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return 0
	}
	return len(v.PortTable)
}

// switchPortsFromModel reads the port count out of a switch model code: the
// first run of digits after the "US" prefix, wherever it sits (US8P150 is 8,
// USW-24-POE is 24, USM8P is 8, USL24P is 24, USW-Pro-48 is 48). A model
// without digits (USMINI, USW-Flex) has no known count.
func switchPortsFromModel(model string) int {
	rest := strings.TrimPrefix(model, "US")
	start := strings.IndexFunc(rest, isDigit)
	if start < 0 {
		return 0
	}
	rest = rest[start:]
	end := 0
	for end < len(rest) && isDigit(rune(rest[end])) {
		end++
	}
	// 16 bits is far more ports than any switch has.
	n, err := strconv.ParseInt(rest[:end], 10, 16)
	if err != nil {
		return 0
	}
	return int(n)
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }
