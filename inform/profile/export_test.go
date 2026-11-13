package profile_test

import (
	"os"
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
func classRules(t *testing.T, name string) []rule {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var out []rule
	for _, l := range strings.Split(string(data), "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Split(l, "\t")
		out = append(out, rule{class: profile.Class(f[0]), pattern: f[2], segs: strings.Split(f[2], ".")})
	}
	return out
}
