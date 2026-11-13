package profile_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/jacobalberty/go-unifi/inform/profile"
)

// The values below are invented test data, not values of any real network.

func site() profile.Site {
	return profile.Site{
		Country:        840,
		LocaleTimezone: "Test/Zone",
		SystemTimezone: "TST0",
		Analytics:      false,
		Users:          []profile.User{{Name: "admin", PasswordHash: "$6$testsalt$testhash", Shell: "/bin/sh"}},
		SSH:            profile.SSH{Enabled: true, PasswordAuth: true, Interfaces: []string{"br0"}},
		NTPServers:     []string{"ntp1.example.test", "ntp2.example.test"},
		Syslog:         profile.Syslog{Level: 5, Remote: &profile.RemoteSyslog{IP: "192.0.2.1", Port: 514, Key: "test-key", Encrypt: true}},
		Netconsole:     &profile.Netconsole{Host: "192.0.2.2", Port: 5514},
		Controller: profile.Controller{
			Version: "0.0.0", CfgCapInfo: "0x0", IDP: true, CrashLogs: false,
			Key: "test-key", MCIP: "http://192.0.2.3:8080/inform", SiteID: "site-id", ReporterID: "reporter-id",
			SiteAnonID: "anon-site", AnonCtlrID: "anon-controller",
		},
		Mesh: profile.Mesh{Enabled: false, ESSID: "mesh-test", PSK: "mesh-psk", Version: 1},
	}
}

func psk(id, ssid string, vlan int, bands ...profile.Band) profile.Network {
	return profile.Network{
		ID: id, SSID: ssid, Security: profile.WPAPersonal, PSK: "test-passphrase", VLAN: vlan, Bands: bands,
		IAPPKey: "0123456789abcdef0123456789abcdef",
	}
}

func eap(id string) profile.Network {
	return profile.Network{
		ID: id, SSID: "corp", Security: profile.WPAEnterprise, IAPPKey: "fedcba9876543210fedcba9876543210",
		Radius: &profile.Radius{
			Auth: profile.Server{IP: "192.0.2.10", Port: 1812, Secret: "radius-secret"},
			Acct: &profile.Server{IP: "192.0.2.10", Port: 1813, Secret: "radius-secret"},
		},
	}
}

func u7lt(t *testing.T) *profile.Profile {
	t.Helper()
	p, ok := profile.Lookup("u7lt")
	if !ok {
		t.Fatal("U7LT has no profile")
	}
	return p
}

func renderFor(t *testing.T, p *profile.Profile, in profile.Inputs) profile.Document {
	t.Helper()
	d, err := profile.Render(p, in)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func render(t *testing.T, in profile.Inputs) profile.Document {
	t.Helper()
	d, err := profile.Render(u7lt(t), in)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// Every rendered key has a class in the capture's classification, for the
// document with no networks and for documents with several kinds of network.
func TestEveryKeyIsClassified(t *testing.T) {
	for _, m := range profile.Models() {
		p, _ := profile.Lookup(m.Code)
		t.Run(m.Code, func(t *testing.T) { everyKeyIsClassified(t, p) })
	}
}

func everyKeyIsClassified(t *testing.T, p *profile.Profile) {
	for name, nets := range map[string][]profile.Network{
		"no networks":  nil,
		"psk":          {psk("a", "one", 0)},
		"enterprise":   {eap("b")},
		"vlan and psk": {psk("a", "one", 0), psk("c", "two", 20, profile.Band5G)},
	} {
		doc := renderFor(t, p, profile.Inputs{Site: site(), Networks: nets})
		for _, k := range doc.Keys() {
			if len(p.Classes(k)) == 0 {
				t.Errorf("%s: key %q has no class", name, k)
			}
		}
	}
}

// A render with no network is the base, the tunables and the site keys, and
// nothing else, and it covers every model, tunable and site pattern.
func TestZeroNetworkKeySet(t *testing.T) {
	for _, m := range profile.Models() {
		p, _ := profile.Lookup(m.Code)
		t.Run(m.Code, func(t *testing.T) { zeroNetworkKeySet(t, p) })
	}
}

func zeroNetworkKeySet(t *testing.T, p *profile.Profile) {
	doc := renderFor(t, p, profile.Inputs{Site: site()})

	want := map[string]bool{}
	for k := range p.Base() {
		want[k] = true
		if !slices.Contains(p.Classes(k), profile.ClassModel) {
			t.Errorf("base key %q is not a model key", k)
		}
	}
	for k := range p.Defaults() {
		want[k] = true
		if !slices.Contains(p.Classes(k), profile.ClassTunable) {
			t.Errorf("tunable %q is not a tunable key", k)
		}
	}
	for _, k := range doc.Keys() {
		if want[k] {
			continue
		}
		cs := p.Classes(k)
		if !slices.Contains(cs, profile.ClassSite) && !slices.Contains(cs, profile.ClassTunable) {
			t.Errorf("key %q (classes %v) is neither base, tunable nor site", k, cs)
		}
		want[k] = true
	}
	for k := range doc {
		if !want[k] {
			t.Errorf("unexpected key %q", k)
		}
	}
	for k := range want {
		if _, ok := doc[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
	// The only keys not network class that are not in the base are tunable or
	// site: nothing of class network may appear without a network, unless it
	// is also a model key.
	for _, k := range doc.Keys() {
		cs := p.Classes(k)
		if slices.Equal(cs, []profile.Class{profile.ClassNetwork}) {
			t.Errorf("network-only key %q in a render with no network", k)
		}
	}
	// Every model, tunable and site rule of the classification is exercised,
	// except the optional blocked-channel list.
	for _, rule := range classRules(t, p.Model.Code) {
		if rule.class == profile.ClassNetwork || rule.pattern == "radio.N.blklst" {
			continue
		}
		if !slices.ContainsFunc(doc.Keys(), func(k string) bool { return rule.matches(k) }) {
			t.Errorf("no key of the zero-network render matches %s pattern %q", rule.class, rule.pattern)
		}
	}
}

func section(k string) string { return k[:strings.Index(k, ".")] }

// Adding one network on both bands to a site that already has one on the same
// VLAN adds exactly the keys the capture's controller added: wireless 66,
// aaa 56, netconf 12, radio 6 and bridge 2, and no other key is added or
// changes.
func TestAddingANetworkAddsTheObservedKeys(t *testing.T) {
	for _, m := range profile.Models() {
		p, _ := profile.Lookup(m.Code)
		t.Run(m.Code, func(t *testing.T) {
			before := renderFor(t, p, profile.Inputs{Site: site(), Networks: []profile.Network{psk("a", "one", 0)}})
			after := renderFor(t, p, profile.Inputs{Site: site(), Networks: []profile.Network{psk("a", "one", 0), psk("b", "two", 0)}})

			for k, v := range before {
				if got, ok := after[k]; !ok || got != v {
					t.Errorf("key %q changed from %q to %q (present: %v)", k, v, got, ok)
				}
			}
			added := map[string]int{}
			for k := range after {
				if _, ok := before[k]; !ok {
					added[section(k)]++
				}
			}
			want := deltas(t, m.Code)
			for s, n := range want {
				if added[s] != n {
					t.Errorf("%s: %d keys added, want %d", s, added[s], n)
				}
			}
			for s, n := range added {
				if _, ok := want[s]; !ok {
					t.Errorf("%d keys added in unexpected section %q", n, s)
				}
			}
		})
	}
}

func TestVLANAddsABridge(t *testing.T) {
	doc := render(t, profile.Inputs{Site: site(), Networks: []profile.Network{psk("a", "one", 0), psk("b", "two", 20)}})
	for k, want := range map[string]string{
		"vlan.1.id": "20", "vlan.1.devname": "eth0", "bridge.2.devname": "br0.20", "bridge.2.port.1.devname": "eth0.20",
		"aaa.3.br.devname": "br0.20", "bridge.1.port.2.devname": "wifi0ap0",
	} {
		if got := doc[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestEnterprise(t *testing.T) {
	doc := render(t, profile.Inputs{Site: site(), Networks: []profile.Network{eap("b")}})
	for k, want := range map[string]string{
		"aaa.1.wpa.key.1.mgmt": "WPA-EAP", "aaa.1.radius.auth.1.port": "1812", "aaa.1.radius.acct.1.port": "1813",
	} {
		if got := doc[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestTunables(t *testing.T) {
	d := render(t, profile.Inputs{Site: site()})
	if d["radio.1.channel"] != "auto" || d["radio.2.channel"] != "auto" {
		t.Errorf("channels default to %q and %q, want auto", d["radio.1.channel"], d["radio.2.channel"])
	}
	if _, ok := d["radio.1.blklst"]; ok {
		t.Error("blocked channels are set by default")
	}
	d = render(t, profile.Inputs{Site: site(), Tunables: map[string]string{"radio.1.channel": "6", "radio.1.blklst": "12,13"}})
	if d["radio.1.channel"] != "6" || d["radio.1.blklst"] != "12,13" {
		t.Errorf("overrides not applied: %q %q", d["radio.1.channel"], d["radio.1.blklst"])
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	in := profile.Inputs{Site: site(), Networks: []profile.Network{psk("a", "one", 0), eap("b"), psk("c", "three", 7, profile.Band2G)}}
	first := render(t, in).String()
	for range 20 {
		if got := render(t, in).String(); got != first {
			t.Fatal("two renders of the same inputs differ")
		}
	}
}

func TestUnsupportedInputsAreErrors(t *testing.T) {
	bad := func(mutate func(*profile.Inputs)) profile.Inputs {
		in := profile.Inputs{Site: site(), Networks: []profile.Network{psk("a", "one", 0)}}
		mutate(&in)
		return in
	}
	for name, in := range map[string]profile.Inputs{
		"guest":                bad(func(i *profile.Inputs) { i.Networks[0].Guest = true }),
		"open":                 bad(func(i *profile.Inputs) { i.Networks[0].Security = "open" }),
		"short passphrase":     bad(func(i *profile.Inputs) { i.Networks[0].PSK = "short" }),
		"no id":                bad(func(i *profile.Inputs) { i.Networks[0].ID = "" }),
		"duplicate id":         bad(func(i *profile.Inputs) { i.Networks = append(i.Networks, psk("a", "two", 0)) }),
		"bad vlan":             bad(func(i *profile.Inputs) { i.Networks[0].VLAN = 5000 }),
		"bad iapp key":         bad(func(i *profile.Inputs) { i.Networks[0].IAPPKey = "xyz" }),
		"unknown band":         bad(func(i *profile.Inputs) { i.Networks[0].Bands = []profile.Band{"6g"} }),
		"enterprise no radius": bad(func(i *profile.Inputs) { i.Networks[0].Security = profile.WPAEnterprise }),
		"unknown tunable":      bad(func(i *profile.Inputs) { i.Tunables = map[string]string{"radio.1.cwm.mode": "1"} }),
		"bad tunable value":    bad(func(i *profile.Inputs) { i.Tunables = map[string]string{"radio.1.channel": "x"} }),
		"line break":           bad(func(i *profile.Inputs) { i.Networks[0].SSID = "a\nb" }),
		"no country":           bad(func(i *profile.Inputs) { i.Site.Country = 0 }),
		"no users":             bad(func(i *profile.Inputs) { i.Site.Users = nil }),
		"no controller key":    bad(func(i *profile.Inputs) { i.Site.Controller.Key = "" }),
		"ssh without a port":   bad(func(i *profile.Inputs) { i.Site.SSH.Interfaces = nil }),
		"too many networks": bad(func(i *profile.Inputs) {
			for n := range 9 {
				i.Networks = append(i.Networks, psk("x"+string(rune('a'+n)), "extra", 0))
			}
		}),
	} {
		doc, err := profile.Render(u7lt(t), in)
		if err == nil {
			t.Errorf("%s: rendered without error", name)
		}
		if doc != nil {
			t.Errorf("%s: returned a (partial) document with the error", name)
		}
	}
	if _, err := profile.Render(nil, profile.Inputs{Site: site()}); err == nil {
		t.Error("rendered for a model with no profile")
	}
}

// No rendered value comes from nowhere: the secrets and identifiers of a
// document are exactly the ones in Inputs.
func TestSecretsComeFromInputs(t *testing.T) {
	p := u7lt(t)
	in := profile.Inputs{Site: site(), Networks: []profile.Network{psk("a", "one", 0)}}
	doc := render(t, in)
	given := map[string]bool{}
	for _, v := range []string{
		in.Site.Users[0].PasswordHash, in.Site.Syslog.Remote.Key, in.Site.Controller.Key, in.Site.Controller.MCIP,
		in.Site.Controller.SiteID, in.Site.Controller.ReporterID, in.Site.Controller.SiteAnonID, in.Site.Controller.AnonCtlrID,
		in.Site.Mesh.PSK, in.Networks[0].PSK, in.Networks[0].IAPPKey,
	} {
		given[v] = true
	}
	for _, k := range doc.Keys() {
		if p.Secret(k) && !given[doc[k]] {
			t.Errorf("secret key %q has a value that is not from the inputs", k)
		}
	}
}

func TestModels(t *testing.T) {
	ms := profile.Models()
	if len(ms) == 0 {
		t.Fatal("no models")
	}
	for _, m := range ms {
		if _, ok := profile.Lookup(m.Code); !ok || m.Kind != profile.KindAccessPoint || len(m.Radios) == 0 || m.Status == "" {
			t.Errorf("model %+v is incomplete", m)
		}
		// The table is the source of Classify.
		if k, n := profile.Classify(m.Code, "", 0); k != m.Kind || n != m.Ports {
			t.Errorf("Classify(%s) = %v, %d; the table says %v, %d", m.Code, k, n, m.Kind, m.Ports)
		}
	}
	if _, ok := profile.Lookup("U7PG2"); ok {
		t.Error("U7PG2 has a profile")
	}
}

func TestClassify(t *testing.T) {
	for _, c := range []struct {
		model, display string
		portTable      int
		kind           profile.Kind
		ports          int
	}{
		{"U7LT", "UAP-AC-Lite", 0, profile.KindAccessPoint, 0},
		{"u7lt", "", 0, profile.KindAccessPoint, 0},
		{"U7PG2", "", 0, profile.KindAccessPoint, 0},
		{"U7IW", "UAP-AC-IW", 0, profile.KindAccessPoint, 2},
		{"US8P150", "", 0, profile.KindSwitch, 8},
		{"US8P150", "", 10, profile.KindSwitch, 10},
		{"USW-24-POE", "", 0, profile.KindSwitch, 24},
		{"USMINI", "", 0, profile.KindSwitch, 0},
		{"UDM-Pro", "", 0, profile.KindGateway, 0},
		{"XYZ", "", 0, profile.KindUnknown, 0},
	} {
		if k, n := profile.Classify(c.model, c.display, c.portTable); k != c.kind || n != c.ports {
			t.Errorf("Classify(%q, %q, %d) = %v, %d; want %v, %d", c.model, c.display, c.portTable, k, n, c.kind, c.ports)
		}
	}
}
