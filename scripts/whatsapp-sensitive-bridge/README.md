# Sensitive WhatsApp transport

This package is a canonical, loopback-only Baileys process for low-level
sensitive-delivery evidence. It does not import the ordinary WhatsApp bridge
or its adapter, session, socket, queue, indexes, logger, hooks, formatting, or
retry paths. It does not mint authorization or user-facing receipts; a later
trusted host launcher must verify the transport identity, validate the returned
evidence, and bind that evidence into its own immutable receipt.

Production is disabled unless the host supplies a fresh inherited capability
and all canonical launcher arguments. The sensitive session must be paired and
provisioned offline to a **different WhatsApp account** from the ordinary
bridge. Pairing is intentionally absent here. Startup requires both exact
provider-canonical account identities and fails closed if they match, if stored
auth identifies the wrong account, or if the live socket identity drifts. The
two identities must use the same provider namespace (`s.whatsapp.net` or
`lid`); a cross-namespace comparison is rejected as unverifiable rather than
assumed to represent different accounts.
The launcher must also supply the canonical ordinary session path solely for
filesystem identity and separation checks. Both paths must be canonical and
absolute, with no symbolic-link or non-directory existing component. The
ordinary directory must already exist. A missing sensitive directory is
created as `0700` only after a no-write preflight proves lexical and resolved
separation from the captured ordinary directory. The process rejects resolved
equality or nesting and device/inode aliases. It never inspects auth contents
under the ordinary path. The sensitive directory must be owned by the
launching UID and have mode exactly `0700`; unsafe parent ownership or write
permissions, pre-existing broader sensitive permissions, and identity drift
around auth loading or later auth operations all fail closed.

## Trusted-host obligations

Before enablement, process spawn, any send, and acceptance of any evidence, the
trusted host must compare the complete returned transport identity to immutable,
reviewed allowlisted expected values. That comparison includes
`manifest_sha256`, `source_sha256`, `package_sha256`, `lock_sha256`, the exact
package/lock identity fields, and the Baileys commit, version, lock integrity,
and `baileys_tree_sha256`. Self-reported hashes only describe the running tree;
they are not their own trust anchor, and neither is npm's git-dependency
integrity warning. The host integration supplies and protects the allowlist.

The trusted host must impose and enforce a hard process deadline, terminating
the bridge when that deadline expires. It must also continuously and
independently monitor the live ordinary-account identity and disable/terminate
sensitive delivery if that identity drifts. These remain mandatory integration
controls: filesystem path validation proves neither process lifetime nor the
live identity of the separate ordinary account. Portable Node path checks do
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

## Evidence semantics

One request pre-reserves one exact pinned-format message ID and invokes one
`sendMessage` with exact text and `linkPreview: null`. Numeric `SERVER_ACK` is
only sender-companion/provider-fanout evidence and cannot succeed an attempt.
Only an exact destination `DELIVERY_ACK`, `READ`, or `PLAYED` update can produce
the internal `provider_accepted` outcome. Send and acknowledgement timeouts are
never retried and remain post-submission ambiguous.

The audited dependency is
`@whiskeysockets/baileys@01047debd81beb20da7b7779b08edcb06aa03770`.
Reproduce the install from this directory with:

```sh
npm ci --no-audit --no-fund
```
