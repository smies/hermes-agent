# Juno--Kite trusted principal

This bundled, opt-in plugin implements the narrow working vertical in
`docs/architecture/adr-juno-kite-trusted-principal-architecture.md`. The same
plugin runs in one of two modes:

- `juno` registers only `consult_kite`. It derives a human principal and the
  canonical Juno conversation from authenticated session ContextVars, resolves
  an opaque Kite context, and sends one bounded signed A2A request to a fixed
  localhost peer.
- `kite` registers the standard `pre_llm_call`, `pre_tool_call`, and
  `transform_llm_output` policy hooks. It binds only authenticated A2A peer
  `juno`, defaults unknown tools to deny, gates mutations by exact canonical
  arguments, and releases only a signed minimized envelope.

The plugin does not register generic A2A discovery, URL, history, context,
peer-selection, or fan-out tools. It does not change Hermes' agent, session,
gateway, hook, or A2A protocols.

## Shared prerequisites

Create one directory that is readable and writable only by the operating-system
account running both profiles. Profiles are logical boundaries, not an OS
sandbox.

```bash
install -d -m 0700 "$HOME/Library/Application Support/Hermes/juno-kite"
```

Generate three independent secrets and place them in each profile's `.env`.
Secrets belong in `.env`; the behavioral settings below belong in
`config.yaml`.

```dotenv
JUNO_KITE_MAPPING_KEY=<at-least-32-random-bytes>
JUNO_KITE_REQUEST_KEY=<different-at-least-32-random-bytes>
JUNO_KITE_RESPONSE_KEY=<different-at-least-32-random-bytes>
JUNO_KITE_A2A_TOKEN=<different-random-bearer-token>
```

The mapping key HMACs the host-selected Juno conversation key before it is
stored. The request and response keys bind the two envelope directions. The
SQLite database contains mappings and a request/replay ledger only--never a
prompt, transcript, memory, raw platform ID, credential, or tool result. The
plugin refuses a directory with group/other permission bits and keeps the DB
file at `0600`.

Use the same `mapping_path`, key values, principal bindings, policy generation,
limits, and semantic policy in both profiles. A principal binding is keyed only
by platform plus the gateway-authenticated platform user ID. Display names and
request text never participate in identity resolution. The example IDs below
are placeholders.

## Juno profile configuration

```yaml
plugins:
  enabled:
    - juno_kite_trusted_principal

# Merge juno_kite into Juno's existing allowlists; keep its current public and
# safe-local toolsets. Do not add the generic a2a toolset. A platform-specific
# allowlist overrides tools.enabled, so the WhatsApp list must include it too.
tools:
  enabled:
    - web
    - clarify
    - juno_kite

platform_toolsets:
  whatsapp:
    - web
    - clarify
    - juno_kite
    - no_mcp

a2a_agents:
  kite:
    url: "http://127.0.0.1:9917"
    auth:
      type: bearer
      token: "${JUNO_KITE_A2A_TOKEN}"
    timeout: 120

juno_kite_trusted_principal:
  enabled: true
  mode: juno
  profile: juno
  mapping_path: "/Users/<operator>/Library/Application Support/Hermes/juno-kite/mapping.sqlite3"
  mapping_key_env: JUNO_KITE_MAPPING_KEY
  request_key_env: JUNO_KITE_REQUEST_KEY
  response_key_env: JUNO_KITE_RESPONSE_KEY
  kite_peer: kite
  kite_url: "http://127.0.0.1:9917"
  kite_plugin: juno_kite_trusted_principal
  policy_generation: "juno-kite-v1"
  principal_bindings:
    - {platform: telegram, user_id: "<authenticated-james-id>", principal: james}
    - {platform: telegram, user_id: "<authenticated-lucy-id>", principal: lucy}
  limits:
    question_chars: 2000
    context_turns: 4
    context_turn_chars: 1000
    handoff_bytes: 8192
    policy_view_chars: 8000
    output_chars: 4000
    response_bytes: 16384
    turn_ttl_seconds: 120
  policy:
    principals:
      james: {trust_class: trusted-family, disclose: [own, shared]}
      lucy: {trust_class: trusted-family, disclose: [own, shared]}
    tool_classes:
      read: [read_file]
      mutating: [write_file]
    action_rules: []
```

`kite_peer` and `kite_url` are both required and must resolve to the same
configured peer. Only plain HTTP loopback hosts are accepted because this
vertical is host-local. Bearer authentication is mandatory. The plugin posts
directly to that configured A2A JSON-RPC URL; Agent Card data cannot redirect
the request.

Keep Juno's deliberately low-privilege public web and safe local utilities
enabled. Its profile guidance should say:

> Use the current principal-isolated session and Juno memory first. Use direct
> public web and safe local tools when they are sufficient. Call
> `consult_kite` only when local/session context is insufficient or Kite's
> private authority is required. Never place identity, authority, destination,
> policy, credentials, or a whole transcript in the call.

Do not enable unfiltered profile-wide `session_search` for person-specific
recall. In a shared Juno profile, `MEMORY.md` and `USER.md` may contain only
agent-wide facts safe for every principal. Existing per-user group/session
isolation remains the person-specific continuity boundary.

## Kite profile configuration

Use the same `juno_kite_trusted_principal` block as Juno, changing only `mode`
and `profile`. Kite must also enable the bundled inbound A2A platform plugin:

```yaml
plugins:
  enabled:
    - a2a-platform
    - juno_kite_trusted_principal

platforms:
  a2a:
    enabled: true
    extra:
      port: 9917

a2a:
  trusted_peers: [juno]

juno_kite_trusted_principal:
  enabled: true
  mode: kite
  profile: default
  mapping_path: "/Users/<operator>/Library/Application Support/Hermes/juno-kite/mapping.sqlite3"
  mapping_key_env: JUNO_KITE_MAPPING_KEY
  request_key_env: JUNO_KITE_REQUEST_KEY
  response_key_env: JUNO_KITE_RESPONSE_KEY
  kite_peer: kite
  kite_url: "http://127.0.0.1:9917"
  kite_plugin: juno_kite_trusted_principal
  policy_generation: "juno-kite-v1"
  principal_bindings:
    - {platform: telegram, user_id: "<authenticated-james-id>", principal: james}
    - {platform: telegram, user_id: "<authenticated-lucy-id>", principal: lucy}
  limits:
    question_chars: 2000
    context_turns: 4
    context_turn_chars: 1000
    handoff_bytes: 8192
    policy_view_chars: 8000
    output_chars: 4000
    response_bytes: 16384
    turn_ttl_seconds: 120
  policy:
    principals:
      james: {trust_class: trusted-family, disclose: [own, shared]}
      lucy: {trust_class: trusted-family, disclose: [own, shared]}
    tool_classes:
      read: [read_file]
      mutating: [write_file]
    action_rules: []
```

`profile` must equal Kite's real active Hermes profile; it is not a role name.
Use `profile: <actual-active-profile>` generically. In this commissioned
configuration (not a claim of live deployment), Kite's intended active profile
is `default`, so the concrete safe value is `profile: default` as shown
above--do not create or assume a profile literally named `kite`.

Configure Kite's bind and inbound credential in the `default` profile's `.env`
so the existing A2A adapter listens only on loopback and authenticates the
bearer as the literal peer identity `juno`:

```dotenv
A2A_HOST=127.0.0.1
A2A_PORT=9917
A2A_PEER_TOKENS=juno:<same-value-as-JUNO_KITE_A2A_TOKEN>
```

The Juno peer URL must remain exactly `http://127.0.0.1:9917`, and its bearer
token must be the same value assigned to peer `juno` above. The top-level
`platforms.a2a` and `a2a.trusted_peers` shapes are intentional Hermes config;
do not nest the platform beneath `gateway`.

Action rules are intentionally empty by default. To authorize a demonstrated
low-risk mutation, add one rule with a literal principal, the canonical tool
name, and every argument including defaults. For example, an isolated test-only
write would be shaped as follows (do not copy its destination into production):

```yaml
juno_kite_trusted_principal:
  policy:
    principals:
      james: {trust_class: trusted-family, disclose: [own, shared]}
      lucy: {trust_class: trusted-family, disclose: [own, shared]}
    tool_classes:
      read: [read_file]
      mutating: [write_file]
    action_rules:
      - principal: james
        tool: write_file
        arguments:
          path: /an/operator-approved/exact/path.txt
          content: "the exact approved content"
          encoding: utf-8
```

The `action_rules` list must stay nested at
`juno_kite_trusted_principal.policy.action_rules`; a top-level list is ignored.

Aliases, missing defaults, extra keys, changed destinations/content, wildcard
rules, a second use, and stale turn/policy bindings deny. Action-capable Kite
toolsets should remain disabled until the deny-path tests and an operator canary
pass for the deployed configuration.

Audit Kite's enabled plugin inventory before activation. The standard hook
manager uses the first non-empty `transform_llm_output` result, so no other
enabled hook may return transformed output for this A2A lane. Likewise, no
other `pre_tool_call` hook may mutate tool arguments. This plugin does not
replace or special-case the standard hook composition rules.

## Enable, health, reload, and rollback

Before enabling, run the focused and regression commands listed in the frozen
contract with a temporary `HERMES_HOME`. Then perform these checks without a
private provider or production action:

1. Run `hermes plugins list` for the active `default` Kite profile and confirm
   both `a2a-platform` and `juno_kite_trusted_principal` are enabled. Run the
   corresponding `hermes -p juno plugins list` command and confirm only the
   trusted-principal plugin is required there.
2. Run `hermes -p juno tools` and confirm `consult_kite` is exposed while
   `a2a_call`, `a2a_history`, `a2a_discover`, and `a2a_orchestrate` are absent.
3. Start or restart Kite's active default profile only:
   `hermes gateway restart`.
4. Verify `http://127.0.0.1:9917/health` returns healthy and logs show both
   plugins loaded with no configuration error. Logs from this plugin contain
   only opaque `corr-...` labels and error classes.
5. Send a synthetic request with an intentionally wrong bearer and confirm it
   is rejected before agent dispatch. Then run a synthetic authenticated-Juno
   canary. Evidence is a signed bounded
   answer for the expected opaque context plus deny results for a wrong bearer,
   wrong context, unknown tool, and changed action argument. Do not use a real
   private provider or real mutation for the canary.
6. Restart Juno only: `hermes -p juno gateway restart`.

Configuration and keys are read at plugin initialization, so policy generation,
bindings, limits, key, or mode changes require targeted restarts of both
affected profiles. Changing an exact action rule requires restarting Kite;
changing Juno's peer or binding configuration requires restarting Juno.

Rollback is recoverable and does not delete state:

1. Remove `juno_kite_trusted_principal` from `plugins.enabled` in Juno and
   Kite. If Kite has no other approved A2A use, also remove `a2a-platform`
   from Kite's `plugins.enabled` and disable `platforms.a2a`.
2. Restart only the Juno gateway and Kite's active `default` gateway.
3. Retain the owner-only mapping DB unless the operator separately approves
   archival/deletion.

The historical `gateway.trusted_private_read.enabled` setting remains `false`.
This plugin neither reads nor changes it.
