package profile_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jacobalberty/go-unifi/inform/profile"
)

type rule struct {
	class   profile.Class
	pattern string
	segs    []string
}

func (r rule) matches(key string) bool {
	segs := strings.Split(key, ".")
	if len(segs) != len(r.segs) {
		return false
	}
	for i, s := range r.segs {
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

// classRules reads the classification file the profile embeds, independently
// of the package, so that a test can check the package against the file.
func classRules(t *testing.T, code string) []rule {
	t.Helper()
	var out []rule
	for _, name := range []string{"classes.txt", "extra-classes.txt"} {
		data, err := os.ReadFile(filepath.Join("models", code, name))
		if err != nil {
			if name == "extra-classes.txt" && os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		out = append(out, parseRules(string(data))...)
	}
	return out
}

func parseRules(data string) []rule {
	var out []rule
	for l := range strings.SplitSeq(data, "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Split(l, "\t")
		out = append(out, rule{class: profile.Class(f[0]), pattern: f[2], segs: strings.Split(f[2], ".")})
	}
	return out
}

// deltas reads the model's golden: the keys one added network must add.
func deltas(t *testing.T, code string) map[string]int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("models", code, "deltas.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Added map[string]int `json:"added_by_section"`
	}
	if err := json.Unmarshal(data, &d); err != nil || len(d.Added) == 0 {
		t.Fatalf("deltas.json of %s: %v", code, err)
	}
	return d.Added
}
