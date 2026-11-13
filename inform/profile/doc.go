// Package profile holds what is known about UniFi device models and renders
// the complete system.cfg a controller sends an access point.
//
// A device REPLACES its whole configuration with the system_cfg of a setparam
// (in a capture of a real controller provisioning a UAP-AC-Lite, the device's
// /tmp/system.cfg was identical to the document, key for key), so a document
// is either complete for a model or must not be sent. Render therefore only
// works for models that have a Profile, and returns an error for any input it
// cannot render rather than a partial document.
//
// Every key of a document has one of four classes:
//
//   - model: fixed by the hardware and firmware; the Profile's Base.
//   - tunable: an operator can change it (channel, width, power, ...); the
//     Profile lists each with its default and the values it accepts.
//   - site: controller-wide (users, ssh, ntp, syslog, controller ids, mesh);
//     the caller supplies them in Site.
//   - network: exists because a wifi network or VLAN is configured; rendered
//     from Inputs.Networks.
//
// The model table is also the source of inform.Inform.Classify, so the
// supported-device matrix and device classification cannot drift apart.
//
// The package does no logging and has no telemetry.
package profile
