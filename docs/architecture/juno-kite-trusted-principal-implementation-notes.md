# Juno--Kite trusted-principal implementation notes

This branch commissions the implementation described by
`adr-juno-kite-trusted-principal-architecture.md`; it does not claim a live
deployment.

## TDD evidence

RED was captured before any production plugin files existed:

```text
$ python3 -c 'from plugins.juno_kite_trusted_principal.runtime import TrustedPrincipalRuntime'
Traceback (most recent call last):
  ...
ModuleNotFoundError: No module named 'plugins.juno_kite_trusted_principal'
```

The focused pytest command was also attempted first, but the isolated worker
runtime had no `python` executable and its system `python3` did not have
pytest installed. Final verification evidence is recorded in the task report.

The correction pass likewise added the real A2A frame, redirect, request
credential, hook identifier, database race/path, exact-expiry, config-load,
and toolset-exposure regressions before changing their owning implementation
boundaries. The immutable candidate's independent RED evidence was:

```text
real security.wrap_inbound('juno', signed_request) -> JUNO--KITE POLICY: DENIED
focused plugin run -> 62 passed, 1 failed (concurrent DB observed mode 0644)
302 loopback reproducer -> redirect target received Authorization: Bearer canary
```

This worker's pytest attempts remained dependency-blocked (`python` absent;
system `python3`: `No module named pytest`). A direct post-test/pre-finalization
concurrency check also exposed `sqlite3.OperationalError: database is locked`
at concurrent `PRAGMA journal_mode = WAL`; the store now retries only that
bounded initialization transition. Final direct and host-required verification
is listed in the task report.
