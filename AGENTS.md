# AGENTS.md

go-unifi is a Go library for the UniFi device protocol (see README.md).

- Commits are Conventional Commits (`type(scope): subject`); every commit to
  `main` drives an automatic release. Do not amend, fixup or force-push on an
  open pull request: fix review and CI findings in new commits.
- Before pushing: `go test -race -shuffle=on -count=1 ./...`,
  `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run ./...`
  and `go fix -diff ./...` (must print nothing).
- The library does no logging and has no telemetry. Add a dependency only when
  neither the standard library nor an existing dependency covers the need.
- Never commit values from a real network: passphrases, hashes, keys, ids,
  addresses. Test data is invented, or key names only.
- **Adding support for a device model: follow
  [docs/adding-a-model.md](docs/adding-a-model.md).** A model is a directory under
  `inform/profile/models/`; its data comes from the capture analyzer's output.
  Do not read a capture's raw data directories without the user's say-so.
