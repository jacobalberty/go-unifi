package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{"-header", "-key", "e2c930683af3945e4d0d58d37a78c2a6", "../../inform/testdata/aes_snappy.dat"}, nil, &out, &errOut)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(bytes.TrimSpace(out.Bytes())) || !strings.Contains(out.String(), `"model": "U7PG2"`) {
		t.Fatalf("output %.200s", out.String())
	}
	if !strings.Contains(errOut.String(), "flags=encrypted|snappy") {
		t.Fatalf("header %q", errOut.String())
	}
	if err := run([]string{"../../inform/testdata/aes_snappy.dat"}, nil, &out, &errOut); err == nil {
		t.Error("default key decoded an adopted device's packet")
	}
	if err := run(nil, nil, &out, &errOut); err == nil {
		t.Error("no files accepted")
	}
}
