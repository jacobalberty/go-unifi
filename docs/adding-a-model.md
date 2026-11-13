# Adding a supported access point

A model is a directory, `inform/profile/models/<MODEL CODE>/`. Adding one is adding
that directory; the loader, `Inform.Classify` and the golden tests pick it up
without Go changes, **unless** the model's document differs in shape from the
existing families (see [When the tests fail](#when-the-tests-fail)).

Read [`inform/profile/doc.go`](../inform/profile/doc.go) first. A device REPLACES its
whole configuration with the `system_cfg` it is sent, so a profile is either
complete or must not exist. If you cannot make the golden tests pass, do not
commit a half-working profile and do not weaken a test: report what is missing.

## Where the data comes from: the capture analyzer

The input is the output of the capture analysis tool (a throwaway tool kept
outside this repository, run on a pcap of a real controller provisioning a real
device; see its README). It only produces a profile when its report says
**RECOGNISED** and every check in `report.md` passes. If the capture is not
recognised, stop: do not hand-edit around a failed check; give the user the
`report.md` and the redacted `packets.jsonl` and ask them to extend the tool.

| Analyzer output | Becomes | How |
|---|---|---|
| `profile.json` `model`, `display`, `kind`, `ports`, `radios[]` | `model.json` | Copy the fields. Add `family`, `status`, and `provenance` (see below). |
| `profile.json` `source.firmware` | `model.json` `provenance.firmware` | Copy. |
| `base.system.cfg` (or `profile.json` `base`, `base_order`) | `base.cfg` | Copy, keeping its order. Replace the header comment with the model, firmware and "derived by subtraction". |
| `key-classes.txt` | `classes.txt` | Copy **verbatim**. Never edit it by hand; if it is wrong, fix the analyzer and re-run. |
| `profile.json` `tunable_observed` | the *list of keys* of `tunables.json` | Use the key names only. **The values are one site's choices, not defaults.** `radio.1.x` and `radio.2.x` become `radio.{N}.x` with `bands`. |
| nothing | `vap.json`, the defaults and checks of `tunables.json`, `deltas.json`, `extra-classes.txt` | The analyzer does not produce these. See below. |

`profile.json`'s `site_keys` and `network_key_patterns` are not copied: they are
covered by `Site`, `Network` and `renderVAP` in `render.go`. Check them (below).

## The files

`model.json`:
```json
{"code": "U7LT", "display": "UAP-AC-Lite", "kind": "access_point", "ports": 0,
 "family": "madwifi-dual", "status": "capture-derived",
 "provenance": {"firmware": "6.8.2.15592", "note": "one capture ..."},
 "radios": [{"index": 1, "phy": "wifi0", "inform_name": "ng", "band": "2g"}, ...]}
```
- The directory name must equal `code`. Only access points have profiles.
- `status` is `capture-derived` for every new model. It becomes
  `hardware-verified` only in a change that says which device, which firmware, and
  that a rendered document was compared with the device's `/tmp/system.cfg`.
  Never set it on your own judgment.
- `family` groups models whose documents share a shape. Use an existing family
  only if the golden tests pass for the new model; otherwise see below.

`tunables.json`: one entry per tunable key, each with `key` (`{N}` is the radio
index), optional `bands`, `default` (or `"optional": true` for a setting that is
absent unless an operator sets it), `check` (exactly one of `enum`,
`auto_or_int` `[min, max]`, `channel_list`), and **`source`**: where the default
comes from, in words. The loader refuses an entry without one.

Defaults rules, which are the easy place to go wrong:
- A default is what an unconfigured controller would send. It is **never** copied
  from `tunable_observed`; those are the capture owner's settings.
- Use the factory (pre-adopt) config and the controller's behaviour to establish
  it (e.g. channel: the device's factory value is `0`, the controller sends
  `auto`). If you cannot establish it, say `UNVERIFIED` in `source` and choose the
  most conservative value the firmware is known to accept, or make the setting
  `optional`.
- Regulatory settings (country code) are not tunables: `Site.Country` supplies them.
- The allowed values in `check` must be tokens you have seen or know the firmware
  accepts. Do not invent tokens.

`vap.json`: per band, `pureg`, `dtim`, and extra `wireless.N.*` keys that the
band's networks carry (the U7LT's 2.4 GHz networks carry minimum-rate keys, its 5 GHz
networks do not). Take these from the non-secret, non-identifier keys of a
network in the decrypted document. The analyzer's output does not contain
values for network keys, so you need the decrypted document: **ask the user, name
the exact keys you want to read, and read only those** (never passphrases, password
hashes, the authkey, ids or secrets; see the rules below).

`deltas.json`: `added_by_section`: how many keys one added both-band network adds,
per first key segment, to a site that already has a network on the same VLAN.
Derive it from two provisioned documents of the same site (before/after adding
a network), counting new keys by section. Do not guess it, and do not set it to
whatever the renderer currently produces.

`extra-classes.txt` (optional, same format as `classes.txt`): key patterns the
renderer supports for this model that the capture did not contain (the U7LT's
WPA-enterprise keys). Say in a comment where the names come from. Anything here
is UNVERIFIED for the model.

## Check the capture against the renderer

Run the golden tests (they loop over every model directory):

```sh
go test -race -shuffle=on -count=1 ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run ./...
go fix -diff ./...   # must print nothing
```

They check, for the new model: every rendered key is classified; a zero-network
render is exactly base + tunables + site, covering every model, tunable and site
pattern of `classes.txt`; and one added network adds exactly `deltas.json`.

### When the tests fail

- *No key of the zero-network render matches site pattern X*: the capture has a
  site key `Site` cannot produce. Add the input to `Site` and `renderSite` (a
  breaking-looking but additive change), with a test.
- *Key set or delta differs for networks*: the model's VAP keys differ from the
  existing family's. This is a **new family**: add a branch in `render.go` keyed on
  `Model.Family` (it is recorded but nothing branches on it yet; the first
  model that needs it adds the first branch), and do not change the existing
  family's output: its tests must still pass untouched.
- *Base key is not a model-class key*, or a tunable is not tunable-class: the
  files disagree with `classes.txt`; fix the file, not the class.

## Rules while doing this (they apply to the data you read)

- The capture directory also holds wifi passphrases, password hashes and the
  authkey. Do not read `revengdata/`, `result-forget/` or `out/` unless the user
  has said you may, and then only the keys they named, and only the non-secret,
  non-identifier ones. Do not print secrets; to learn the shape of a secret print
  its length and character set.
- The only values that may be committed are the model-class base, tunable
  defaults you established, and per-band VAP constants. Never commit a site value,
  SSID, passphrase, id, key, hash, MAC or address from a capture. Test data is
  invented (see `render_test.go`).
- Do not edit the analyzer's outputs by hand; do not weaken or skip a golden
  test; do not mark anything `hardware-verified`.

## The pull request

State in the description, plainly:
- which capture it came from (device, firmware, one site) and that the base was
  derived by subtraction and never observed with zero networks;
- the `source` of every default and which are UNVERIFIED;
- what is in `extra-classes.txt` and why;
- that the document was not compared with a device (`status: capture-derived`),
  and the hardware test: factory-reset the model, adopt it, `cat /tmp/system.cfg`,
  and compare it with the rendered document key for key.

Use Conventional Commits (`feat(inform): support the <model>`); every commit
drives an automatic release.
