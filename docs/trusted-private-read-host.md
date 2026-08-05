# Trusted private-read gateway host

The trusted private-read host is absent by default. The gateway considers it
only when `gateway.trusted_private_read` is an explicit version-1 mapping with
`enabled: true`. Disabled or invalid configuration leaves the service-gated
tool out of model schemas.

The mapping contains only generic host configuration:

- canonical absolute `state_dir`, `key_file`, and `allowlist_file` paths;
- the exact `openfga_version: "1.18.2"` target;
- immutable capability IDs with operation, resource type, and field names;
- bounded worker poll and lease durations.

The state directory must be owner-owned mode `0700`. Key and allowlist files
must be owner-owned regular files with one link, mode `0600`, and no symlink or
replaceable path component. The gateway continuously checks their filesystem
identity, mode, ownership, and content seal. The key file contains only the
existing authorization-store HMAC authorities. The allowlist binds the full
reviewed sensitive transport identity, including the manifest, source,
package, lock, exact Baileys pin/integrity, and installed tree digest.

Configuration cannot import a module or inject a factory. Production
composition is gateway-owned so an external adapter cannot self-assert the
requester, approver, requested fields, policy stage, account binding, task or
claim, destination, or delivery authority. The current tree deliberately has
no built-in production composition for those authorities, so enabling this
mapping leaves the private runtime unavailable. Closed synthetic services are
used only by tests to verify the authorization and isolated-delivery protocol.
This is a fail-closed service-composition gap, not a production-readiness
claim.

A future concrete composition must derive immutable requester context from the
exact authenticated inbound `MessageEvent`, perform two uncached checks using
the `HIGHER_CONSISTENCY` request preference, monitor two distinct linked-device
sessions whose live provider-canonical account identities match, and supply the
exact allowlisted sensitive transport only after durable claim. Unknown,
mismatched, or drifting PN/LID/device topology fails closed. Provider credentials and
connection details belong in owner-only host-managed files or inherited
descriptors, never in `config.yaml`.

The persisted `consistency="strongest"` marker records that outbound request
preference; it is not treated as a server-issued linearizability proof. Every
positive task still requires two independent checks plus the store's existing
runtime, policy, and model attestation.

On startup the gateway acquires the authorization coordinator and reconciles
durable work before atomically installing the runtime. It removes the runtime
and reaps the services on shutdown, account or transport drift, policy/runtime
attestation failure, configuration-file drift, cancellation, or any
`BaseException`. Health output contains booleans only.

WhatsApp authentication is always separate. Use
`hermes whatsapp provision --role ordinary|sensitive`; the command validates
and reuses a ready session before requesting a phone-number pairing code. Use
`--validate-only` for non-sensitive machine-readable readiness and
`--reprovision` only for an intentional replacement. Production sockets cannot
request a pairing code, and there is no QR fallback.

Both linked-device sessions intentionally authenticate the same public Juno
account. Their auth roots, device credentials, processes, sockets, generations,
and capabilities remain separate. This reduces application capability and
process coupling; it does not prevent sender-companion plaintext fan-out into
WhatsApp account history or another linked device, and it provides no boundary
against WhatsApp-account or same-UID/process-memory compromise.
