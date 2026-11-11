package inform

import "testing"

func TestConfig(t *testing.T) {
	c := NewConfig()
	for _, kv := range [][2]string{{KeyCfgVersion, "1"}, {KeyAuthKey, "00112233445566778899aabbccddeeff"}, {KeyUseAESGCM, "true"}, {KeyCfgVersion, "2"}} {
		if err := c.Set(kv[0], kv[1]); err != nil {
			t.Fatal(err)
		}
	}
	want := "cfgversion=2\nauthkey=00112233445566778899aabbccddeeff\nuse_aes_gcm=true\n"
	if got := c.String(); got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
	c.Delete(KeyAuthKey)
	if _, ok := c.Get(KeyAuthKey); ok || c.Len() != 2 {
		t.Fatal("delete failed")
	}

	p, err := ParseConfig("# comment\r\nb=1\n\na=x=y\n")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := p.Get("a"); v != "x=y" || p.String() != "b=1\na=x=y\n" {
		t.Fatalf("parsed = %q", p.String())
	}

	for _, kv := range [][2]string{{"", "v"}, {"a=b", "v"}, {"a\nb", "v"}, {"k", "line1\nline2"}} {
		if err := c.Set(kv[0], kv[1]); err == nil {
			t.Errorf("Set(%q, %q) accepted", kv[0], kv[1])
		}
	}
	if _, err := ParseConfig("novalue\n"); err == nil {
		t.Error("line without = accepted")
	}
}

func TestMgmtConfig(t *testing.T) {
	c, err := MgmtConfig{AuthKey: captureKey, CfgVersion: "7", UseAESGCM: true}.Config()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := c.String(), "cfgversion=7\nauthkey=e2c930683af3945e4d0d58d37a78c2a6\nuse_aes_gcm=true\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if _, err := (MgmtConfig{AuthKey: []byte("short"), CfgVersion: "1"}).Config(); err == nil {
		t.Error("short key accepted")
	}
	if _, err := (MgmtConfig{AuthKey: captureKey}).Config(); err == nil {
		t.Error("missing cfgversion accepted")
	}
	if _, err := (MgmtConfig{AuthKey: captureKey, CfgVersion: "a\nb"}).Config(); err == nil {
		t.Error("multi-line cfgversion accepted")
	}
}
