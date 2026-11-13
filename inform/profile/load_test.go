package profile

import (
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

// goodModel is a minimal valid model directory.
func goodModel() fstest.MapFS {
	return fstest.MapFS{
		"models/T1/model.json": {Data: []byte(`{"code":"T1","display":"Test","kind":"access_point","family":"f","status":"capture-derived",
			"radios":[{"index":1,"phy":"wifi0","inform_name":"ng","band":"2g"}]}`)},
		"models/T1/base.cfg":      {Data: []byte("radio.status=enabled\n")},
		"models/T1/classes.txt":   {Data: []byte("model\t-\tradio.status\ntunable\t-\tradio.N.channel\n")},
		"models/T1/vap.json":      {Data: []byte(`{"2g":{"pureg":"0","dtim":"1"}}`)},
		"models/T1/tunables.json": {Data: []byte(`[{"key":"radio.{N}.channel","default":"auto","check":{"auto_or_int":[1,196]},"source":"test"}]`)},
		"models/T1/deltas.json":   {Data: []byte(`{"added_by_section":{"aaa":1}}`)},
	}
}

func TestLoadAcceptsAValidModel(t *testing.T) {
	ps, err := load(goodModel())
	if err != nil || len(ps) != 1 {
		t.Fatalf("load: %v, %d profiles", err, len(ps))
	}
	if got := ps[0].Defaults()["radio.1.channel"]; got != "auto" {
		t.Errorf("default = %q", got)
	}
}

// Every way a model directory can be wrong is an error at load, not at render.
func TestLoadRejectsBrokenModels(t *testing.T) {
	for name, mutate := range map[string]func(fstest.MapFS){
		"directory named differently": func(m fstest.MapFS) { m["models/T2/model.json"] = m["models/T1/model.json"] },
		"missing base":                func(m fstest.MapFS) { delete(m, "models/T1/base.cfg") },
		"empty base":                  func(m fstest.MapFS) { m["models/T1/base.cfg"] = &fstest.MapFile{Data: []byte("# nothing\n")} },
		"base key not model class": func(m fstest.MapFS) {
			m["models/T1/base.cfg"] = &fstest.MapFile{Data: []byte("radio.status=enabled\nwho.knows=1\n")}
		},
		"repeated base key": func(m fstest.MapFS) {
			m["models/T1/base.cfg"] = &fstest.MapFile{Data: []byte("radio.status=a\nradio.status=b\n")}
		},
		"bad status": func(m fstest.MapFS) {
			m["models/T1/model.json"] = &fstest.MapFile{Data: []byte(strings.Replace(string(m["models/T1/model.json"].Data), "capture-derived", "probably-fine", 1))}
		},
		"unknown json field": func(m fstest.MapFS) {
			m["models/T1/vap.json"] = &fstest.MapFile{Data: []byte(`{"2g":{"pureg":"0","dtim":"1","dtm":"2"}}`)}
		},
		"missing band in vap.json": func(m fstest.MapFS) { m["models/T1/vap.json"] = &fstest.MapFile{Data: []byte(`{}`)} },
		"tunable without source": func(m fstest.MapFS) {
			m["models/T1/tunables.json"] = &fstest.MapFile{Data: []byte(`[{"key":"radio.{N}.channel","default":"auto","check":{"auto_or_int":[1,196]}}]`)}
		},
		"tunable default fails its check": func(m fstest.MapFS) {
			m["models/T1/tunables.json"] = &fstest.MapFile{Data: []byte(`[{"key":"radio.{N}.channel","default":"x","check":{"auto_or_int":[1,196]},"source":"t"}]`)}
		},
		"tunable not tunable class": func(m fstest.MapFS) {
			m["models/T1/tunables.json"] = &fstest.MapFile{Data: []byte(`[{"key":"radio.status","default":"a","check":{"enum":["a"]},"source":"t"}]`)}
		},
		"bad class line": func(m fstest.MapFS) {
			m["models/T1/classes.txt"] = &fstest.MapFile{Data: []byte("model radio.status\n")}
		},
		"switch profile": func(m fstest.MapFS) {
			m["models/T1/model.json"] = &fstest.MapFile{Data: []byte(strings.Replace(string(m["models/T1/model.json"].Data), "access_point", "switch", 1))}
		},
	} {
		m := goodModel()
		mutate(m)
		if _, err := load(m); err == nil {
			t.Errorf("%s: loaded without error", name)
		}
	}
}

// The directories on disk are exactly the models in the table, and each has
// the files a model needs, so a file left out of the embed shows up here.
func TestEveryModelDirectoryIsInTheTable(t *testing.T) {
	entries, err := os.ReadDir("models")
	if err != nil {
		t.Fatal(err)
	}
	var onDisk []string
	for _, e := range entries {
		if e.IsDir() {
			onDisk = append(onDisk, e.Name())
		}
	}
	if len(onDisk) != len(table) {
		t.Fatalf("%d model directories on disk, %d models in the table", len(onDisk), len(table))
	}
	for _, p := range table {
		for _, f := range []string{"model.json", "base.cfg", "classes.txt", "tunables.json", "vap.json", "deltas.json"} {
			if _, err := os.Stat("models/" + p.Model.Code + "/" + f); err != nil {
				t.Errorf("%s: %v", p.Model.Code, err)
			}
		}
	}
}
