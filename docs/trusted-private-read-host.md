# Trusted private-read gateway host

The trusted private-read host is absent by default. The gateway considers it
only when `gateway.trusted_private_read` is an explicit version-1 mapping with
`enabled: true`. Disabled or invalid configuration leaves the service-gated
tool out of model schemas.

The mapping contains only generic host configuration:

- canonical absolute `state_dir`, `key_file`, and `allowlist_file` paths;
- a reviewed `services_module` exporting
  `build_trusted_private_read_services(gateway, config)`;
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

The reviewed services module returns the closed
`TrustedPrivateReadHostServices` object. It derives immutable context only from
the authenticated inbound event, performs uncached policy checks at the
`HIGHER_CONSISTENCY` request preference with all local/application caches
disabled, monitors the live ordinary and sensitive
account identities in one provider namespace, supplies the exact sensitive
transport registration only after a durable claim, performs the private read,
and closes all resources. Provider credentials and connection details stay in
owner-only files or inherited descriptors managed by that module; they do not
belong in `config.yaml`.

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
