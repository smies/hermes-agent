# Sensitive WhatsApp transport

This package is a canonical, loopback-only Baileys process for low-level
sensitive-delivery evidence. It does not import the ordinary WhatsApp bridge
or its adapter, session, socket, queue, indexes, logger, hooks, formatting, or
retry paths. It does not mint authorization or user-facing receipts. The
default-off gateway owner verifies the transport identity and validates
returned evidence. The version-2 Juno MVP has a code-owned loopback submission
composition; configuration still cannot select arbitrary executable services.
Provisioning and deployment remain explicit operator gates.

Every process entrypoint is a minimal launcher that imports only Node built-ins
until qualification completes. The launcher contains an exact digest of the
byte-for-byte `transport-manifest.json`; that manifest binds the package, lock,
installed Baileys tree, and every executable module beneath the launcher. The
trusted Python host separately binds the launcher source digest, avoiding a
circular self-hash claim. Only then does `launcher.js` dynamically import the
sensitive bridge core, or `provision_launcher.js` import the offline
provisioner. Directly importing either core is inert and creates no socket,
listener, or auth state.

Production is disabled unless the host supplies a fresh inherited capability
and all canonical launcher arguments. The sensitive session must be paired and
provisioned offline as a second linked device for the **same WhatsApp account**
as the ordinary bridge. Pairing is intentionally absent here. Startup requires
both exact provider-canonical account identities and fails closed if they do
not match, if either identity is unknown, if PN/LID topology is incomplete, if
stored auth identifies the wrong account, or if the live socket identity
drifts.
The launcher must also supply the canonical ordinary session path solely for
filesystem identity and separation checks. Both paths must be canonical and
absolute, with no symbolic-link or non-directory existing component. The
ordinary directory must already exist. A missing sensitive directory is
created as `0700` only after a no-write preflight proves lexical and resolved
separation from the captured ordinary directory. The process rejects resolved
equality or nesting and device/inode aliases. Before activation it also rejects
cross-tree hard links, byte-for-byte credential copies, and reused stable
linked-device identity material. The sensitive directory must be owned by the
launching UID and have mode exactly `0700`; unsafe parent ownership or write
permissions, pre-existing broader sensitive permissions, and identity drift
around auth loading or later auth operations all fail closed.

This is a session/process capability boundary, not a WhatsApp-account
plaintext boundary. Baileys sender-companion fan-out can place the private
message in the shared account history and deliver it to another linked Juno
device. The ordinary bridge may necessarily decrypt that fan-out in process
memory before its earliest callback fence discards the authenticated
`key.fromMe` event. Other linked devices, account compromise, and compromise
by code running under the same UID remain outside this guarantee.

## Trusted-host obligations

Before enablement, process spawn, any send, and acceptance of any evidence, the
trusted host must compare the complete returned transport identity to immutable,
reviewed allowlisted expected values. That comparison includes
`launcher_sha256`, `manifest_sha256`, `source_sha256`, `package_sha256`,
`lock_sha256`, `verifier_sha256`, `node_modules_tree_sha256`, the exact
npm spec, lock version/resolved/integrity, installed name/version/package bytes,
`baileys_tree_sha256`, and the exact `juno-sensitive-submit-v2` contract. The
published Git head is recorded only as reviewed
release metadata because the npm package does not claim a `gitHead`; it is not
artifact ancestry proof. Self-reported hashes only describe the running tree;
they are not their own trust anchor, and neither is npm's git-dependency
integrity warning. The host integration supplies and protects the allowlist.

The trusted host must impose and enforce a hard process deadline, terminating
the bridge when that deadline expires. It must also continuously and
independently monitor the live ordinary-account identity and disable/terminate
sensitive delivery if either identity drifts or the same-account relationship
cannot be proved. These remain mandatory integration controls: filesystem path
validation proves neither process lifetime nor live account topology. Portable
Node path checks do
not provide a descriptor-anchored `openat` guarantee; replacement by the same
UID in the small check-to-operation window remains within trusted-host and OS
isolation scope.

## Provisioning prerequisite

The reviewed Baileys pin warns that disabling every history-sync type prevents
initial LID mappings from being learned. Offline provisioning must therefore
complete the account's LID bootstrap and persist it in this package's dedicated
auth directory before production enablement. The production socket sets
`shouldSyncHistoryMessage` to false, as well as `syncFullHistory` and
`fireInitQueries` to false, so it will not use history or offline-sync payloads.
The host must treat a missing or stale LID mapping as unavailable and return the
session to offline provisioning; it must not relax these production settings.

Run `hermes whatsapp provision --role sensitive` in an interactive terminal.
It first performs a read-only readiness check and reuses a valid session. Only
a missing, invalid, stale, mismatched, or explicitly reprovisioned session
reaches Baileys `requestPairingCode`; the phone number crosses on bounded stdin
and the short code crosses a dedicated inherited operator pipe. Production
startup contains no pairing operation and there is no QR fallback.

## Evidence semantics

The only authenticated route is exact `POST /v1/submit`. Both identity
observation and plaintext submission use closed, authenticated request bodies
on that route. Legacy
`/v1/send` and direct `transport.send()` delivery are not published. Submit
pre-reserves one exact pinned-format message ID, invokes one `sendMessage` with
exact text and `linkPreview: null`, and returns `submitted` only after that
promise resolves with matching message/account/destination correlation. It
does not wait for an acknowledgement and never labels that result delivered or
read. A timeout, mismatch, or unknown result is terminal for that request and
is not automatically retried. Its authenticated
JSON body carries the exact integer `expires_at_us` deadline and
`contract_version: juno-sensitive-submit-v2`. The Python coroutine checks the
deadline at entry and immediately before HTTP issue; the authenticated Node
handler checks immediately before delivery dispatch; and the delivery core
checks again with no event-loop yield before `sendMessage`. Exact expiry is
stale. Missing, malformed, incoherent, or more-than-five-minute deadlines fail
closed without invoking the provider send primitive.

Immediately before the final provider call, the receiver creates and fsyncs an
owner-only `O_CREAT|O_EXCL` tombstone under the dedicated
`sensitive-receiver-replay` authority. The filename is a SHA-256 of the logical
request ID; the bounded record contains only the request-ID digest and a digest
of the complete profile/mode/runtime/session/account/destination/expiry/payload/
topology descriptor. Tombstones are permanent: expiry does not make a logical
request ID reusable. The authority is initialized only before any other Juno
state exists; missing replay artifacts in a non-pristine state directory fail
closed. This intentionally trades unbounded long-term inode/disk growth for
durable one-shot semantics. Operators must monitor the directory and expand or
migrate the whole sealed authority; deleting or pruning individual tombstones
makes the receiver fail closed and is not supported.

The Python supervisor is the sole writer of the child's inherited stdin control
pipe. EOF/error disables HTTP and provider authority, tears down the socket, and
exits the child, including after supervisor `SIGKILL` or `os._exit`. Graceful
shutdown closes that pipe before TERM/KILL escalation and waits for the exact
child. The exact-launcher test provider seam requires two inherited owner-only
file descriptors plus a parent-PID/process-generation/expiry-bound authority;
it is absent from launch descriptors, scrubbed by the production supervisor,
and exists only to intercept the final synthetic test send below the reviewed
launcher/core boundary without WhatsApp network access.

The audited dependency is exactly
`@whiskeysockets/baileys@7.0.0-rc14`, resolved from its npm tarball with the
integrity recorded in `transport-manifest.json`.
Reproduce the install from this directory with:

```sh
npm ci --no-audit --no-fund
```
