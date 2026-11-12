package inform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// Inform is a device's periodic report. Only commonly needed fields are
// typed; Raw holds the complete message.
type Inform struct {
	MAC          string `json:"mac"`
	Model        string `json:"model"`
	ModelDisplay string `json:"model_display"`
	Version      string `json:"version"` // firmware version
	Serial       string `json:"serial"`
	Hostname     string `json:"hostname"`
	IP           string `json:"ip"`
	InformURL    string `json:"inform_url"`
	// ConfigVersion is the cfgversion of the configuration the device runs.
	ConfigVersion string `json:"cfgversion"`
	// Default is true while the device is in its factory default state,
	// i.e. not adopted by any controller.
	Default bool  `json:"default"`
	Uptime  int64 `json:"uptime"`

	Raw json.RawMessage `json:"-"`
}

// ParseInform decodes a device's inform message.
func ParseInform(msg []byte) (*Inform, error) {
	var in Inform
	if err := json.Unmarshal(msg, &in); err != nil {
		return nil, fmt.Errorf("inform: decoding message: %w", err)
	}
	in.Raw = bytes.Clone(msg)
	return &in, nil
}

// Response is a controller reply: Noop, SetParam, Upgrade, Reboot, Cmd or
// SetDefault.
type Response interface {
	responseType() string
}

// MarshalResponse encodes r with its "_type" and the server time.
func MarshalResponse(r Response, now time.Time) ([]byte, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, err
	}
	typ, _ := json.Marshal(r.responseType())
	ts, _ := json.Marshal(strconv.FormatInt(now.UnixMilli(), 10))
	fields["_type"] = typ
	fields["server_time_in_utc"] = ts
	return json.Marshal(fields)
}

// Noop tells the device nothing changed and when to inform next.
type Noop struct {
	// Interval is the number of seconds until the next inform.
	Interval int `json:"interval"`
}

func (Noop) responseType() string { return "noop" }

// SetParam pushes configuration. Each *Config field is a key=value
// document (see Config); ConfigVersion is echoed back by the device as
// cfgversion once it has applied them.
type SetParam struct {
	ManagementConfig string `json:"mgmt_cfg,omitempty"`
	SystemConfig     string `json:"system_cfg,omitempty"`
	PortConfig       string `json:"port_cfg,omitempty"`
	AnalogConfig     string `json:"analog_cfg,omitempty"`
	AuthorizedGuests string `json:"authorized_guests,omitempty"`
	BlockedStations  string `json:"blocked_stations,omitempty"`
	ConfigVersion    string `json:"cfg_version,omitempty"`
}

func (SetParam) responseType() string { return "setparam" }

// Upgrade asks the device to install firmware from URL.
type Upgrade struct {
	URL      string `json:"url"`
	Version  string `json:"version"`
	DeviceID string `json:"device_id,omitempty"`
}

func (Upgrade) responseType() string { return "upgrade" }

// Reboot asks the device to restart.
type Reboot struct {
	DeviceID string `json:"device_id,omitempty"`
}

func (Reboot) responseType() string { return "reboot" }

// Cmd runs a device command, e.g. Cmd{Command: "locate"}.
type Cmd struct {
	Command  string `json:"cmd"`
	DeviceID string `json:"device_id,omitempty"`
}

func (Cmd) responseType() string { return "cmd" }

// SetDefault tells the device to factory reset itself: it forgets its
// configuration and its key and goes back to the state of a new device, which
// informs with DefaultKey and waits to be adopted. It is the reply a UniFi
// controller sends when an adopted device is "forgotten", and it carries no
// fields beyond the type and the server time:
//
//	{"_type":"setdefault","server_time_in_utc":"1794511845763"}
type SetDefault struct{}

func (SetDefault) responseType() string { return "setdefault" }
