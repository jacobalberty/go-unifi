// Command inform decodes UniFi inform packets and prints their JSON.
//
//	inform [-key HEX] FILE...
//
// FILE is a raw packet as POSTed to /inform ("-" reads standard input).
// The key defaults to the one unadopted devices use.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jacobalberty/go-unifi/inform"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "inform:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("inform", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyHex := fs.String("key", hex.EncodeToString(inform.DefaultKey()), "AES key as 32 hex digits (a device's authkey)")
	header := fs.Bool("header", false, "print the packet header to standard error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return fmt.Errorf("no packet files given")
	}
	key, err := hex.DecodeString(*keyHex)
	if err != nil {
		return fmt.Errorf("-key: %w", err)
	}
	for _, name := range fs.Args() {
		var b []byte
		if name == "-" {
			b, err = io.ReadAll(stdin)
		} else {
			b, err = os.ReadFile(filepath.Clean(name))
		}
		if err != nil {
			return err
		}
		p, err := inform.Parse(b)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if *header {
			_, _ = fmt.Fprintf(stderr, "%s: mac=%s flags=%s version=%d data_version=%d payload=%d bytes\n",
				name, p.MAC, p.Flags, p.Version, p.DataVersion, len(p.Payload))
		}
		msg, err := p.Decode(key)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if _, err := fmt.Fprintf(stdout, "%s\n", msg); err != nil {
			return err
		}
	}
	return nil
}
