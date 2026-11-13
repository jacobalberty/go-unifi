package inform

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMarshalResponse(t *testing.T) {
	now := time.UnixMilli(1700000000123)
	for _, tc := range []struct {
		r    Response
		want map[string]any
	}{
		{Noop{Interval: 10}, map[string]any{"_type": "noop", "interval": 10.0}},
		{SetParam{ManagementConfig: "a=b\n", ConfigVersion: "abc"}, map[string]any{"_type": "setparam", "mgmt_cfg": "a=b\n", "cfg_version": "abc"}},
		{Upgrade{URL: "http://x/fw.bin", Version: "6.0"}, map[string]any{"_type": "upgrade", "url": "http://x/fw.bin", "version": "6.0"}},
		{Reboot{}, map[string]any{"_type": "reboot"}},
		{Cmd{Command: "locate"}, map[string]any{"_type": "cmd", "cmd": "locate"}},
		{SetDefault{}, map[string]any{"_type": "cmd", "cmd": "setdefault"}},
	} {
		b, err := MarshalResponse(tc.r, now)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if got["server_time_in_utc"] != "1700000000123" {
			t.Errorf("%T: server time %v", tc.r, got["server_time_in_utc"])
		}
		delete(got, "server_time_in_utc")
		if len(got) != len(tc.want) {
			t.Errorf("%T: %v, want %v", tc.r, got, tc.want)
		}
		for k, v := range tc.want {
			if got[k] != v {
				t.Errorf("%T: %s = %v, want %v", tc.r, k, got[k], v)
			}
		}
	}
}

// SetDefault goes out as the "setdefault" command, with nothing else but the
// type and the server time.
func TestSetDefaultIsACommand(t *testing.T) {
	b, err := MarshalResponse(SetDefault{}, time.UnixMilli(1794511845763))
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"_type":"cmd","cmd":"setdefault","server_time_in_utc":"1794511845763"}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
}

func TestParseInformKeepsRaw(t *testing.T) {
	in, err := ParseInform([]byte(`{"mac":"aa:bb:cc:dd:ee:ff","default":true,"extra":[1]}`))
	if err != nil || !in.Default || in.MAC != "aa:bb:cc:dd:ee:ff" || !json.Valid(in.Raw) {
		t.Fatalf("inform = %+v, %v", in, err)
	}
	if _, err := ParseInform([]byte(`not json`)); err == nil {
		t.Error("bad JSON accepted")
	}
}

func TestParseInformCapture(t *testing.T) {
	p, err := Parse(readCapture(t))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := p.Decode(captureKey)
	if err != nil {
		t.Fatal(err)
	}
	in, err := ParseInform(msg)
	if err != nil {
		t.Fatal(err)
	}
	if in.MAC != "f0:9f:c2:79:63:90" || in.Model != "U7PG2" || in.ModelDisplay != "UAP-AC-Pro-Gen2" ||
		in.Version != "3.9.27.8537" || in.ConfigVersion != "a14317aa23e349e6" || in.Default ||
		in.InformURL != "http://unifi:8080/inform" || in.IP != "192.168.7.239" {
		t.Fatalf("inform = %+v", in)
	}
}
