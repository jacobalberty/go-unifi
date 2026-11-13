package inform

import "testing"

func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		model, display, raw string
		kind                DeviceKind
		ports               int
	}{
		{"U7PG2", "", "", KindAccessPoint, 0},
		{"U6LR", "", "", KindAccessPoint, 0},
		{"UAP-AC-Pro", "", "", KindAccessPoint, 0},
		{"UAP-AC-IW", "", "", KindAccessPoint, 2},
		{"U7XX", "AC IW", "", KindAccessPoint, 2},
		{"US8P150", "", "", KindSwitch, 8},
		{"USW-24-POE", "", "", KindSwitch, 24},
		{"USMINI", "", "", KindSwitch, 0},
		{"US16P150", "", `{"port_table":[{},{},{}]}`, KindSwitch, 3},
		{"US99999999999999999999", "", "", KindSwitch, 0},
		{"UDMPRO", "", "", KindGateway, 0},
		{"mystery", "", "", KindUnknown, 0},
		{"", "", "", KindUnknown, 0},
	} {
		in := &Inform{Model: tc.model, ModelDisplay: tc.display, Raw: []byte(tc.raw)}
		kind, ports := in.Classify()
		if kind != tc.kind || ports != tc.ports {
			t.Errorf("Classify(%q, %q) = %q, %d; want %q, %d", tc.model, tc.display, kind, ports, tc.kind, tc.ports)
		}
	}
}
