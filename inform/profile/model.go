package profile

import (
	"strings"
)

// Kind is the product line of a UniFi device.
type Kind string

const (
	// KindUnknown is a device whose model this package does not recognise.
	KindUnknown     Kind = ""
	KindAccessPoint Kind = "access_point"
	KindSwitch      Kind = "switch"
	KindGateway     Kind = "gateway"
)

// Band is a radio band.
type Band string

const (
	Band2G Band = "2g"
	Band5G Band = "5g"
)

// Radio is one radio of a model.
type Radio struct {
	Index      int    // N in radio.N.*
	Phy        string // wifi0, wifi1
	InformName string // the name in the inform's radio_table: ng, na
	Band       Band
}

// Model is a row of the supported-device table.
type Model struct {
	Code    string // model code in the inform: U7LT
	Display string // UAP-AC-Lite
	Kind    Kind
	Ports   int // ports beyond the uplink
	Radios  []Radio
}

// Models returns the models that have a Profile. The result is a copy.
func Models() []Model {
	out := make([]Model, 0, len(table))
	for _, p := range table {
		m := p.Model
		m.Radios = append([]Radio(nil), m.Radios...)
		out = append(out, m)
	}
	return out
}

// Lookup returns the profile of a model code, which is matched without regard
// to case. Models without a profile are not found: no system.cfg can be
// rendered for them.
func Lookup(code string) (*Profile, bool) {
	code = strings.ToUpper(strings.TrimSpace(code))
	for _, p := range table {
		if strings.EqualFold(p.Model.Code, code) {
			return p, true
		}
	}
	return nil, false
}

// A family classifies the models of one product line by the prefix of their
// code, for models that have no row in the table.
type family struct {
	kind     Kind
	prefixes []string
}

var families = []family{
	{KindGateway, []string{"UGW", "UDM", "UDR", "UXG", "UCG", "UDW"}},
	{KindAccessPoint, []string{"U7", "U6", "U5", "U2", "UAP", "UAL", "UHD", "UFL", "UBB", "BZ2", "UWB", "E7", "UK"}},
	{KindSwitch, []string{"US"}},
}

// Classify says what kind of device a model is and how many ports beyond its
// uplink it has. A model in the table answers from its row. Any other model
// is classified by the prefix of its code, whose prefix names the product
// line: U7PG2, U6-LR and UAP-AC-Pro are access points; US8P150 and USW-24-POE
// are switches; UDM-Pro and UXG are gateways. A model that matches nothing is
// KindUnknown with no ports.
//
// display is the model's display name from the inform, and portTable the
// length of its port_table (0 when it sent none). Most access points have no
// port of their own. The in-wall models, whose code or display name ("AC IW")
// contains "IW", have two LAN ports (checked on a UAP-AC-IW; other in-wall
// models may differ). A switch reports portTable when it sent one, else the
// number in its model code (US8P150 is 8, USW-24-POE is 24, USMINI is 0).
// Gateways report 0: their ports are not described by the model code.
func Classify(model, display string, portTable int) (Kind, int) {
	if p, ok := Lookup(model); ok {
		if p.Model.Kind == KindSwitch && portTable > 0 {
			return p.Model.Kind, portTable
		}
		return p.Model.Kind, p.Model.Ports
	}
	model = strings.ToUpper(model)
	for _, f := range families {
		if !hasAnyPrefix(model, f.prefixes...) {
			continue
		}
		switch f.kind {
		case KindAccessPoint:
			if strings.Contains(model, "IW") || strings.Contains(strings.ToUpper(display), "IW") {
				return KindAccessPoint, 2
			}
			return KindAccessPoint, 0
		case KindSwitch:
			if portTable > 0 {
				return KindSwitch, portTable
			}
			return KindSwitch, switchPortsFromModel(model)
		}
		return f.kind, 0
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
	n := 0
	for i := 0; i < len(rest) && isDigit(rune(rest[i])); i++ {
		n = n*10 + int(rest[i]-'0')
		// Far more ports than any switch has: not a port count.
		if n > 1<<15-1 {
			return 0
		}
	}
	return n
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }
