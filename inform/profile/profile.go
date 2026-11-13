package profile

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// kv is one key=value pair of a document.
type kv struct{ k, v string }

// Class says where a key's value comes from. See the package documentation.
type Class string

const (
	ClassModel   Class = "model"
	ClassTunable Class = "tunable"
	ClassSite    Class = "site"
	ClassNetwork Class = "network"
)

// Tunable is a setting an operator can change.
type Tunable struct {
	Key string // the concrete key, e.g. radio.1.channel
	// Default is rendered when the operator has not set the tunable. It is
	// empty for an Optional tunable, which is left out of the document unless set.
	Default  string
	Optional bool
	// Check reports whether a value is acceptable.
	Check func(string) error
}

// Profile is everything the renderer knows about one model.
type Profile struct {
	Model Model
	// Base is the model-class part of the document.
	base []kv
	// Tunables are the settings an operator can change, in document order.
	Tunables []Tunable

	classes []classRule
	vap     map[Band]vapRadio
}

// vapRadio holds what a wifi network's keys contain that depends on the
// radio it runs on.
type vapRadio struct {
	pureg, dtim string
	// wireless are further wireless.N.* keys of the radio's networks.
	wireless []kv
}

// Base returns the model-class keys with their values, in document order.
func (p *Profile) Base() map[string]string {
	m := make(map[string]string, len(p.base))
	for _, e := range p.base {
		m[e.k] = e.v
	}
	return m
}

// Tunable returns the tunable with the given key.
func (p *Profile) Tunable(key string) (Tunable, bool) {
	for _, t := range p.Tunables {
		if t.Key == key {
			return t, true
		}
	}
	return Tunable{}, false
}

// Defaults returns the default value of every non-optional tunable.
func (p *Profile) Defaults() map[string]string {
	m := map[string]string{}
	for _, t := range p.Tunables {
		if !t.Optional {
			m[t.Key] = t.Default
		}
	}
	return m
}

// CheckTunables reports whether every key is a tunable of the model and every
// value acceptable for it.
func (p *Profile) CheckTunables(set map[string]string) error {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t, ok := p.Tunable(k)
		if !ok {
			return fmt.Errorf("profile %s: %q is not a tunable setting", p.Model.Code, k)
		}
		if err := t.Check(set[k]); err != nil {
			return fmt.Errorf("profile %s: %s: %w", p.Model.Code, k, err)
		}
	}
	return nil
}

// A classRule is one line of the key classification: a key pattern whose "N"
// segments stand for an index.
type classRule struct {
	class    Class
	secret   bool
	segments []string
}

// Classes returns the classes a key can belong to, or nil for a key that no
// rule covers. A key can have several: bridge.1.devname is a model key, and
// bridge.2.devname a network key, and the patterns cannot tell them apart.
func (p *Profile) Classes(key string) []Class {
	var out []Class
	segs := strings.Split(key, ".")
	for _, r := range p.classes {
		if r.matches(segs) && !slices.Contains(out, r.class) {
			out = append(out, r.class)
		}
	}
	return out
}

// Secret reports whether the classification marks key as holding a secret.
func (p *Profile) Secret(key string) bool {
	segs := strings.Split(key, ".")
	for _, r := range p.classes {
		if r.secret && r.matches(segs) {
			return true
		}
	}
	return false
}

func (r classRule) matches(segs []string) bool {
	if len(segs) != len(r.segments) {
		return false
	}
	for i, s := range r.segments {
		if s == "N" {
			if segs[i] == "" || strings.Trim(segs[i], "0123456789") != "" {
				return false
			}
		} else if s != segs[i] {
			return false
		}
	}
	return true
}
