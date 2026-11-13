package inform

import (
	"encoding/json"

	"github.com/jacobalberty/go-unifi/inform/profile"
)

// DeviceKind is the product line of a UniFi device. It is the Kind of the
// profile package, whose model table Classify answers from.
type DeviceKind = profile.Kind

const (
	// KindUnknown is a device whose model this package does not recognise.
	KindUnknown     = profile.KindUnknown
	KindAccessPoint = profile.KindAccessPoint
	KindSwitch      = profile.KindSwitch
	KindGateway     = profile.KindGateway
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
	return profile.Classify(in.Model, in.ModelDisplay, portTableLen(in.Raw))
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
