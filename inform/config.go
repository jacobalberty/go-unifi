package inform

import (
	"fmt"
	"strings"
)

// Well-known mgmt_cfg keys.
const (
	KeyAuthKey    = "authkey"     // the device's AES key, 32 hex digits
	KeyCfgVersion = "cfgversion"  // configuration version the device reports back
	KeyUseAESGCM  = "use_aes_gcm" // "true" to switch the device to AES-GCM
	KeyInformURL  = "mgmt.servers.1.url"
)

// Config is a key=value document as used by mgmt_cfg and system_cfg: one
// "key=value" per line. Keys keep their insertion order.
type Config struct {
	keys   []string
	values map[string]string
}

// NewConfig returns an empty Config.
func NewConfig() *Config { return &Config{values: map[string]string{}} }

// ParseConfig reads a key=value document. Blank lines and lines starting
// with "#" are skipped.
func ParseConfig(s string) (*Config, error) {
	c := NewConfig()
	for i, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("inform: config line %d has no '='", i+1)
		}
		if err := c.Set(k, v); err != nil {
			return nil, fmt.Errorf("inform: config line %d: %w", i+1, err)
		}
	}
	return c, nil
}

// Set adds or replaces key. Keys may not be empty or contain "=" or line
// breaks; values may not contain line breaks.
func (c *Config) Set(key, value string) error {
	if key == "" || strings.ContainsAny(key, "=\r\n") {
		return fmt.Errorf("inform: invalid config key %q", key)
	}
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("inform: config value for %q contains a line break", key)
	}
	if _, ok := c.values[key]; !ok {
		c.keys = append(c.keys, key)
	}
	c.values[key] = value
	return nil
}

// Get returns the value of key.
func (c *Config) Get(key string) (string, bool) {
	v, ok := c.values[key]
	return v, ok
}

// Delete removes key.
func (c *Config) Delete(key string) {
	if _, ok := c.values[key]; !ok {
		return
	}
	delete(c.values, key)
	for i, k := range c.keys {
		if k == key {
			c.keys = append(c.keys[:i], c.keys[i+1:]...)
			break
		}
	}
}

// Len returns the number of keys.
func (c *Config) Len() int { return len(c.keys) }

// String renders the document, one "key=value\n" per key.
func (c *Config) String() string {
	var b strings.Builder
	for _, k := range c.keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(c.values[k])
		b.WriteByte('\n')
	}
	return b.String()
}
