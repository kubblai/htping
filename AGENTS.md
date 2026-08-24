# AGENTS.md

Single-file Go CLI/TUI app: HTTP(S) endpoint pinger with a Bubble Tea interface. All application code is in `main.go`; tests in `main_test.go`.

## Traps

- The compiled binaries `htping` and `main` are tracked in git. Rebuilding overwrites them; don't commit fresh binaries unless intended.
- Geolocation uses the free ipapi.co tier, which throttles with HTTP 429 and publishes no reset window (no `Retry-After` header). `TestFetchGeoLocation` skips on `errRateLimited` — never add retries or sleeps against it. `TestCollectAllInfoData` also hits the live internet (google.com).
- Two execution paths still exist behind one shared core (`executeSinglePing`, `buildReportData`, `write*Report`): TUI (`performPing`/`generateReport`/`export*TUI`) and non-TTY (`runSimplePing`/`generateSimpleReport`/`export*`). Which path runs depends on `isTerminal()`: piping stdout (e.g. `./htping example.com | cat`) forces plain-text output — handy for scripted smoke tests, but means user-facing changes should be checked both ways.
- README references a removed `CLAUDE.md` and its feature claims are aspirational in places — trust `main.go` and the flags registered there.

## Test suite

`go test ./...` passes except when offline or rate-limited by external services (see above). Export tests write `test-export.json`/`test-export.html` into the CWD and clean up after themselves.
