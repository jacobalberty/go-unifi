# go-unifi

[![Go Reference](https://pkg.go.dev/badge/github.com/jacobalberty/go-unifi.svg)](https://pkg.go.dev/github.com/jacobalberty/go-unifi)

> **Pre-release.** go-unifi is at 0.x and its API is not stable: do not rely on
> it staying the same between releases. It is currently developed alongside
> [beenfar](https://github.com/jacobalberty/beenfar), which drives its shape, and
> will be refactored for a 1.0.0 release with a more concrete API contract.

A Go implementation of the UniFi device protocol: what UniFi access points
and switches speak to their controller. It has no controller logic of its
own, so you can build a controller, a proxy or a debugging tool on it.

Package [`inform`](inform) covers the inform protocol, which devices POST to
`/inform`:

- packet framing, AES-128-CBC and AES-128-GCM encryption, zlib and snappy
  compression (`Parse`, `Packet.Decode`, `Seal`);
- the device's report (`ParseInform`), what kind of device sent it and how many
  ports it has (`Inform.Classify`), and the controller's replies (`Noop`,
  `SetParam`, `Upgrade`, `Reboot`, `Cmd`, encoded by `MarshalResponse`);
- the `key=value` documents carried by `mgmt_cfg` and `system_cfg` (`Config`);
- an `http.Handler` that does all of the above around your callbacks.

```go
http.Handle("/inform", &inform.Handler{
	// Candidate keys, tried in order. While handing a device a new key,
	// offer the new and the old one until it is seen using the new one.
	Keys: func(ctx context.Context, mac net.HardwareAddr) ([]inform.Key, error) {
		return keysFor(mac) // e.g. pending, current, then {"default", inform.DefaultKey()}
	},
	Serve: func(ctx context.Context, p *inform.Packet, in *inform.Inform, used inform.Key) (inform.Response, error) {
		if !adopted(p.MAC) {
			return nil, inform.ErrUnknownDevice // 404: the device keeps waiting
		}
		return inform.Noop{Interval: 10}, nil
	},
})
```

### Provisioning an access point: package `inform/profile`

A device REPLACES its whole configuration with the `system_cfg` of a `SetParam`
(a capture of a real controller provisioning a UAP-AC-Lite showed the device's
`/tmp/system.cfg` identical to the document, key for key), so a partial document
can leave an access point unusable. Package [`inform/profile`](inform/profile)
holds the supported-device table (also the source of `Inform.Classify`) and a
renderer that builds the *complete* document:

```go
p, ok := profile.Lookup(in.Model) // only models with a profile can be rendered
doc, err := profile.Render(p, profile.Inputs{Tunables: …, Site: …, Networks: …})
sp.SystemConfig = doc.String()
```

`Render` is deterministic and returns an error for any input it cannot render,
never a partial document. Only the UAP-AC-Lite (`U7LT`) has a profile. Every
fact comes from one capture of one site and one firmware (6.8.2.15592); the
package documentation and each model's `model.json` say what is not verified.
A model is a directory under `inform/profile/models/`; see
[docs/adding-a-model.md](docs/adding-a-model.md) to add one.

### Adopting devices and changing keys

A device starts out encrypting with `inform.DefaultKey()`. Adoption hands it
its own key in a `SetParam` whose management config comes from
`inform.MgmtConfig{AuthKey: inform.NewKey(), CfgVersion: …}`. That reply is
sealed with the key the device used, since it does not have the new one yet.

Replies can be lost, so until the device is seen using the new key, `Keys`
should return both: `{"pending", new}` and the old key. `Serve` is told which
one worked (`used.Name`). Once it is `"pending"`, the switch is done: store
the new key as current and drop the old one. The same steps replace a key.

**Taking over devices from another controller.** A device adopted elsewhere
keeps its key when it is pointed at a new controller (by DNS or
`set-inform`). With its `authkey`, extracted from the other controller and
read with `inform.ParseKey`, offer that key as a candidate, then re-key the
device as above. Devices that no candidate key can open are passed to
`Handler.Undecryptable`, with their MAC, so you can list what still needs
credentials.

The only dependency is [github.com/golang/snappy](https://github.com/golang/snappy).
The library does no logging and carries no telemetry.

## inform tool

```sh
go install github.com/jacobalberty/go-unifi/cmd/inform@latest
inform -header -key <authkey hex> packet.bin
```

decodes captured packets and prints their JSON. Without `-key` it uses the
default key of unadopted devices.

## Releases

Releases are automatic. Every push to `main` that adds `feat`, `fix`, `perf`
or breaking commits since the last tag is tagged with the next semantic
version and published with generated release notes, so commit messages must
follow [Conventional Commits](https://www.conventionalcommits.org/) (CI
checks pull requests). While the version is 0.x, breaking changes bump the
minor version. Version 1.0.0 and later major versions are cut by hand.

## Credits

The captured packet in `inform/testdata` comes from
[dmke/inform-inspect](https://github.com/dmke/inform-inspect) (MIT).
