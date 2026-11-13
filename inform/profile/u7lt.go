package profile

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
)

// u7lt is the UAP-AC-Lite (model code U7LT, display name "UAP-AC-Lite").
//
// Provenance: every fact comes from one capture of a real controller
// provisioning one UAP-AC-Lite on firmware 6.8.2.15592. Nothing here was seen
// on a second device, a second site or a second firmware.
func u7lt() *Profile {
	p := &Profile{
		Model: Model{
			Code:    "U7LT",
			Display: "UAP-AC-Lite",
			Kind:    KindAccessPoint,
			Ports:   0,
			Radios: []Radio{
				{Index: 1, Phy: "wifi0", InformName: "ng", Band: Band2G},
				{Index: 2, Phy: "wifi1", InformName: "na", Band: Band5G},
			},
		},
		base:    u7ltBase,
		classes: append(parseClasses(u7ltClasses), radiusRules...),
		vap: map[Band]vapRadio{
			// The 2.4 GHz networks of the capture carried minimum-rate keys
			// the 5 GHz ones did not (66 wireless keys for one SSID on both).
			Band2G: {pureg: "0", dtim: "1", wireless: []kv{
				{"beacon_rate", "1000"},
				{"mgmt_rate", "1000"},
				{"minrate_cck_rates.status", "true"},
				{"minrate_data", "1000"},
			}},
			Band5G: {pureg: "1", dtim: "3"},
		},
	}
	p.Tunables = u7ltTunables(p.Model.Radios)
	return p
}

var (
	enabledDisabled = oneOf("enabled", "disabled")
	channelList     = regexp.MustCompile(`^[0-9]{1,3}(,[0-9]{1,3})*$`)
)

// u7ltTunables lists the tunable settings and their defaults.
//
// Defaults. The capture's values are the capture owner's network, not
// UniFi's defaults, so they were not copied. Where a default is established
// from something other than the capture owner's choice it says so:
//
//   - radio.N.channel is "auto". The factory config of the same AP, before
//     it was adopted, has channel "0"; the provisioned document, written by
//     the controller, has "auto". "0" is the device's own pre-adoption
//     value and "auto" is what a controller sends for an unset channel, so
//     "auto" is the default: it is what an unconfigured controller sends.
//   - bandsteering, stamgr, outdoor, background scan, rf scan and hard noise
//     floor are "disabled", and transmit power is "auto". These are the
//     states of an access point nobody has tuned; the capture agrees, but
//     that is not independent evidence, so they are UNVERIFIED as defaults.
//   - radio.1.blklst (blocked channels) is optional and absent unless set:
//     the capture's value is one site's channel plan.
//   - the country code is not a tunable of the profile: it is a regulatory
//     fact of the site, so Site.Country supplies it and there is no default.
//   - the 2.4 GHz width is HT20 (the usual default); the 5 GHz width is
//     HT40. The 5 GHz value is the one the capture shows and it is NOT
//     established as UniFi's default: it is UNVERIFIED, chosen because it is
//     a token this firmware is known to accept.
func u7ltTunables(radios []Radio) []Tunable {
	ts := []Tunable{
		{Key: "bandsteering.status", Default: "disabled", Check: enabledDisabled},
		{Key: "radio.outdoor", Default: "disabled", Check: enabledDisabled},
		{Key: "stamgr.status", Default: "disabled", Check: enabledDisabled},
	}
	for _, r := range radios {
		pre := "radio." + strconv.Itoa(r.Index) + "."
		ieee, ieeeDefault := oneOf("11nght20", "11nght40"), "11nght20"
		if r.Band == Band5G {
			ieee = oneOf("11naht20", "11naht40", "11acvht20", "11acvht40", "11acvht80")
			ieeeDefault = "11naht40"
		}
		ts = append(ts,
			Tunable{Key: pre + "bgscan.status", Default: "disabled", Check: enabledDisabled},
			Tunable{Key: pre + "channel", Default: "auto", Check: channel},
			Tunable{Key: pre + "hard_noisefloor.status", Default: "disabled", Check: enabledDisabled},
			Tunable{Key: pre + "ieee_mode", Default: ieeeDefault, Check: ieee},
			Tunable{Key: pre + "rfscan", Default: "disabled", Check: enabledDisabled},
			Tunable{Key: pre + "txpower", Default: "auto", Check: txpower},
			Tunable{Key: pre + "txpower_mode", Default: "auto", Check: oneOf("auto", "custom")},
		)
		if r.Band == Band2G {
			ts = append(ts, Tunable{Key: pre + "blklst", Optional: true, Check: func(v string) error {
				if !channelList.MatchString(v) {
					return fmt.Errorf("%q is not a comma-separated list of channels", v)
				}
				return nil
			}})
		}
	}
	return ts
}

func oneOf(values ...string) func(string) error {
	return func(v string) error {
		if slices.Contains(values, v) {
			return nil
		}
		return fmt.Errorf("%q is not one of %v", v, values)
	}
}

func channel(v string) error {
	if v == "auto" {
		return nil
	}
	if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 196 {
		return fmt.Errorf("%q is not \"auto\" or a channel number", v)
	}
	return nil
}

func txpower(v string) error {
	if v == "auto" {
		return nil
	}
	if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 40 {
		return fmt.Errorf("%q is not \"auto\" or a power in dBm (1-40)", v)
	}
	return nil
}
