package profile

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Each model is a directory under models/, named by its model code. Adding a
// model is adding a directory: nothing in Go changes. See
// docs/adding-a-model.md for the files and how to produce them.
//
//go:embed models
var modelFS embed.FS

// table is the supported-device table: the models that have a profile.
var table = mustLoad(modelFS)

func mustLoad(fsys fs.FS) []*Profile {
	ps, err := load(fsys)
	if err != nil {
		panic("profile: " + err.Error())
	}
	return ps
}

// load reads every model directory of fsys.
func load(fsys fs.FS) ([]*Profile, error) {
	dirs, err := fs.ReadDir(fsys, "models")
	if err != nil {
		return nil, err
	}
	var out []*Profile
	seen := map[string]string{}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		p, err := loadModel(fsys, path.Join("models", d.Name()))
		if err != nil {
			return nil, fmt.Errorf("models/%s: %w", d.Name(), err)
		}
		if p.Model.Code != d.Name() {
			return nil, fmt.Errorf("models/%s: model code is %q, the directory must be named after it", d.Name(), p.Model.Code)
		}
		if other, dup := seen[strings.ToUpper(p.Model.Code)]; dup {
			return nil, fmt.Errorf("models/%s: model code also used by %s", d.Name(), other)
		}
		seen[strings.ToUpper(p.Model.Code)] = d.Name()
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Model.Code < out[j].Model.Code })
	return out, nil
}

type modelFile struct {
	Code       string `json:"code"`
	Display    string `json:"display"`
	Kind       Kind   `json:"kind"`
	Ports      int    `json:"ports"`
	Family     string `json:"family"`
	Status     Status `json:"status"`
	Provenance struct {
		Firmware string `json:"firmware"`
		Note     string `json:"note"`
	} `json:"provenance"`
	Radios []struct {
		Index      int    `json:"index"`
		Phy        string `json:"phy"`
		InformName string `json:"inform_name"`
		Band       Band   `json:"band"`
	} `json:"radios"`
}

type checkFile struct {
	Enum        []string `json:"enum"`
	AutoOrInt   []int    `json:"auto_or_int"` // [min, max]
	ChannelList bool     `json:"channel_list"`
}

type tunableFile struct {
	Key      string    `json:"key"` // {N} stands for the radio index
	Bands    []Band    `json:"bands"`
	Default  string    `json:"default"`
	Optional bool      `json:"optional"`
	Check    checkFile `json:"check"`
	Source   string    `json:"source"` // where the default comes from; required
}

type vapFile map[Band]struct {
	PureG    string            `json:"pureg"`
	DTIM     string            `json:"dtim"`
	Wireless map[string]string `json:"wireless"`
}

func readJSON(fsys fs.FS, name string, v any) error {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path.Base(name), err)
	}
	return nil
}

func loadModel(fsys fs.FS, dir string) (*Profile, error) {
	var mf modelFile
	if err := readJSON(fsys, path.Join(dir, "model.json"), &mf); err != nil {
		return nil, err
	}
	m := Model{Code: mf.Code, Display: mf.Display, Kind: mf.Kind, Ports: mf.Ports, Family: mf.Family, Status: mf.Status, Firmware: mf.Provenance.Firmware}
	switch {
	case m.Code == "" || m.Display == "" || m.Family == "":
		return nil, fmt.Errorf("model.json needs code, display and family")
	case m.Kind != KindAccessPoint:
		return nil, fmt.Errorf("model.json: only access points have profiles, not %q", m.Kind)
	case m.Status != StatusCaptureDerived && m.Status != StatusHardwareVerified:
		return nil, fmt.Errorf("model.json: status %q is neither %q nor %q", m.Status, StatusCaptureDerived, StatusHardwareVerified)
	case len(mf.Radios) == 0:
		return nil, fmt.Errorf("model.json: no radios")
	}
	for i, r := range mf.Radios {
		if r.Index != i+1 || r.Phy == "" || r.InformName == "" || (r.Band != Band2G && r.Band != Band5G) {
			return nil, fmt.Errorf("model.json: radio %d is invalid (indices count from 1 in order; phy, inform_name and a 2g or 5g band are required)", i+1)
		}
		m.Radios = append(m.Radios, Radio{Index: r.Index, Phy: r.Phy, InformName: r.InformName, Band: r.Band})
	}

	p := &Profile{Model: m, vap: map[Band]vapRadio{}}
	var err error
	if p.base, err = readBase(fsys, path.Join(dir, "base.cfg")); err != nil {
		return nil, err
	}
	for _, name := range []string{"classes.txt", "extra-classes.txt"} {
		data, err := fs.ReadFile(fsys, path.Join(dir, name))
		if err != nil {
			if name == "extra-classes.txt" {
				continue // optional
			}
			return nil, err
		}
		rules, err := parseClasses(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		p.classes = append(p.classes, rules...)
	}

	var vf vapFile
	if err := readJSON(fsys, path.Join(dir, "vap.json"), &vf); err != nil {
		return nil, err
	}
	for _, r := range m.Radios {
		v, ok := vf[r.Band]
		if !ok || v.PureG == "" || v.DTIM == "" {
			return nil, fmt.Errorf("vap.json: no pureg and dtim for the %s band", r.Band)
		}
		vr := vapRadio{pureg: v.PureG, dtim: v.DTIM}
		keys := make([]string, 0, len(v.Wireless))
		for k := range v.Wireless {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			vr.wireless = append(vr.wireless, kv{k, v.Wireless[k]})
		}
		p.vap[r.Band] = vr
	}

	var tf []tunableFile
	if err := readJSON(fsys, path.Join(dir, "tunables.json"), &tf); err != nil {
		return nil, err
	}
	if p.Tunables, err = expandTunables(tf, m.Radios); err != nil {
		return nil, fmt.Errorf("tunables.json: %w", err)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return p, nil
}

func readBase(fsys fs.FS, name string) ([]kv, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, err
	}
	var out []kv
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || k == "" || seen[k] {
			return nil, fmt.Errorf("base.cfg: bad or repeated line %q", line)
		}
		seen[k] = true
		out = append(out, kv{k, v})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("base.cfg is empty")
	}
	return out, nil
}

// parseClasses reads a key-classes file: "class<TAB>secret|-<TAB>pattern".
func parseClasses(data []byte) ([]classRule, error) {
	var rules []classRule
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		c := Class(f[0])
		if len(f) != 3 || (c != ClassModel && c != ClassTunable && c != ClassSite && c != ClassNetwork) || (f[1] != "secret" && f[1] != "-") {
			return nil, fmt.Errorf("bad line %q (want class<TAB>secret|-<TAB>pattern)", line)
		}
		rules = append(rules, classRule{class: c, secret: f[1] == "secret", segments: strings.Split(f[2], ".")})
	}
	return rules, nil
}

var channelList = regexp.MustCompile(`^[0-9]{1,3}(,[0-9]{1,3})*$`)

func (c checkFile) fn() (func(string) error, error) {
	switch {
	case len(c.Enum) > 0 && !c.ChannelList && c.AutoOrInt == nil:
		values := c.Enum
		return func(v string) error {
			if slices.Contains(values, v) {
				return nil
			}
			return fmt.Errorf("%q is not one of %v", v, values)
		}, nil
	case len(c.AutoOrInt) == 2 && len(c.Enum) == 0 && !c.ChannelList:
		lo, hi := c.AutoOrInt[0], c.AutoOrInt[1]
		return func(v string) error {
			if v == "auto" {
				return nil
			}
			if n, err := strconv.Atoi(v); err != nil || n < lo || n > hi {
				return fmt.Errorf("%q is not \"auto\" or a number from %d to %d", v, lo, hi)
			}
			return nil
		}, nil
	case c.ChannelList && len(c.Enum) == 0 && c.AutoOrInt == nil:
		return func(v string) error {
			if !channelList.MatchString(v) {
				return fmt.Errorf("%q is not a comma-separated list of channels", v)
			}
			return nil
		}, nil
	}
	return nil, fmt.Errorf("check must be exactly one of enum, auto_or_int [min, max] or channel_list")
}

func expandTunables(tf []tunableFile, radios []Radio) ([]Tunable, error) {
	var out []Tunable
	seen := map[string]bool{}
	add := func(t tunableFile, key string) error {
		if seen[key] {
			return fmt.Errorf("%s is listed twice", key)
		}
		seen[key] = true
		check, err := t.Check.fn()
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		if t.Source == "" {
			return fmt.Errorf("%s: source is required: say where the default comes from", key)
		}
		if t.Optional && t.Default != "" {
			return fmt.Errorf("%s: an optional tunable has no default", key)
		}
		if !t.Optional {
			if t.Default == "" {
				return fmt.Errorf("%s: a default is required (or mark it optional)", key)
			}
			if err := check(t.Default); err != nil {
				return fmt.Errorf("%s: its own default: %w", key, err)
			}
		}
		out = append(out, Tunable{Key: key, Default: t.Default, Optional: t.Optional, Check: check})
		return nil
	}
	for _, t := range tf {
		if !strings.Contains(t.Key, "{N}") {
			if len(t.Bands) > 0 {
				return nil, fmt.Errorf("%s: bands only apply to a per-radio key ({N})", t.Key)
			}
			if err := add(t, t.Key); err != nil {
				return nil, err
			}
			continue
		}
		for _, r := range radios {
			if len(t.Bands) > 0 && !slices.Contains(t.Bands, r.Band) {
				continue
			}
			if err := add(t, strings.ReplaceAll(t.Key, "{N}", strconv.Itoa(r.Index))); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// validate checks that the files of a model agree with each other.
func (p *Profile) validate() error {
	for _, e := range p.base {
		if !slices.Contains(p.Classes(e.k), ClassModel) {
			return fmt.Errorf("base.cfg: %q is not a model-class key in classes.txt", e.k)
		}
	}
	for _, t := range p.Tunables {
		if !slices.Contains(p.Classes(t.Key), ClassTunable) {
			return fmt.Errorf("tunables.json: %q is not a tunable-class key in classes.txt", t.Key)
		}
	}
	return nil
}
