# Juno--Kite trusted principal

This bundled, opt-in plugin implements the narrow working vertical in
`docs/architecture/adr-juno-kite-trusted-principal-architecture.md`. The same
plugin runs in one of two modes:

- `juno` registers `consult_kite` plus a fail-closed `pre_gateway_dispatch`
  ingress hook. It derives a human principal and the
  canonical Juno conversation from authenticated session ContextVars, resolves
  an opaque Kite context, and sends one bounded signed A2A request to a fixed
  localhost peer.
- `kite` registers `pre_llm_call`, `pre_tool_call`, the generic veto-only
  `pre_tool_dispatch` integrity hook, and `transform_llm_output`. It binds only
  authenticated A2A peer `juno`, defaults unknown tools to deny, gates
  mutations by exact canonical arguments, and releases only a signed minimized
  envelope.

For an allowlisted WhatsApp group, the ingress hook reads a complete current
roster only from the exact adapter-managed bridge that authenticated the
event. The bridge binds the roster to a one-use challenge, its secret sender
companion fence, runtime, socket generation, group, and proved phone/LID alias
sets. Every human member must bind to exactly one configured principal; an
unknown or ambiguous human yields public-only authority. Group-only principals
are silent in DMs and whenever a required co-principal cannot be proved.
Roster identifiers never enter prompts, ordinary logs, envelopes, or SQLite;
only opaque audience/freshness digests and semantic capability IDs cross the
Juno--Kite boundary.

The plugin does not register generic A2A discovery, URL, history, context,
peer-selection, or fan-out tools. Its only core dependency is Hermes's generic
final handler-boundary veto hook. The gateway's generic pre-dispatch loop also
awaits bounded asynchronous hook results; no core branch knows this plugin's
name.

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
file at `0600`. It authenticates and retains the database fd, serializes each
SQLite operation through a bounded OS file lock, and loads/persists an
ephemeral `:memory:` connection through that fd. SQLite never reopens the
configured pathname after authentication.

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

# Suppress resolver-added or inherited capability classes as a final
# subtraction. These names remain disabled even when credentials or a runtime
# mode would otherwise make their check_fn succeed.
agent:
  disabled_toolsets:
    - a2a
    - bfl
    - delegation
    - file
    - kanban
    - terminal

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
  version: 2
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
    - {platform: whatsapp, user_id: "10000000001@s.whatsapp.net", principal: owner}
    - {platform: whatsapp, user_id: "20000000001@lid", principal: owner}
    - {platform: whatsapp, user_id: "10000000002@s.whatsapp.net", principal: group_member}
    - {platform: whatsapp, user_id: "20000000002@lid", principal: group_member}
  allowed_group_conversations:
    - {platform: whatsapp, chat_id: "300000000000000@g.us"}
  limits:
    question_chars: 2000
    context_turns: 4
    context_turn_chars: 1000
    handoff_bytes: 8192
    policy_view_chars: 8000
    output_chars: 4000
    response_bytes: 16384
    turn_ttl_seconds: 120
    roster_timeout_seconds: 2
  policy:
    principals:
      owner:
        conversation_eligibility: {dm: true, group: true}
        required_group_co_principals: []
        read_capability_ids: [private.own, private.shared]
        action_capability_ids: []
        semantic_policy:
          private.own: {disclose: [own]}
          private.shared: {trust_class: trusted-family, disclose: [shared]}
      group_member:
        conversation_eligibility: {dm: false, group: true}
        required_group_co_principals: [owner]
        read_capability_ids: [private.shared]
        action_capability_ids: []
        semantic_policy:
          private.shared: {trust_class: trusted-family, disclose: [shared]}
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
  version: 2
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
    - {platform: whatsapp, user_id: "10000000001@s.whatsapp.net", principal: owner}
    - {platform: whatsapp, user_id: "20000000001@lid", principal: owner}
    - {platform: whatsapp, user_id: "10000000002@s.whatsapp.net", principal: group_member}
    - {platform: whatsapp, user_id: "20000000002@lid", principal: group_member}
  allowed_group_conversations:
    - {platform: whatsapp, chat_id: "300000000000000@g.us"}
  limits:
    question_chars: 2000
    context_turns: 4
    context_turn_chars: 1000
    handoff_bytes: 8192
    policy_view_chars: 8000
    output_chars: 4000
    response_bytes: 16384
    turn_ttl_seconds: 120
    roster_timeout_seconds: 2
  policy:
    principals:
      owner:
        conversation_eligibility: {dm: true, group: true}
        required_group_co_principals: []
        read_capability_ids: [private.own, private.shared]
        action_capability_ids: []
        semantic_policy:
          private.own: {disclose: [own]}
          private.shared: {trust_class: trusted-family, disclose: [shared]}
      group_member:
        conversation_eligibility: {dm: false, group: true}
        required_group_co_principals: [owner]
        read_capability_ids: [private.shared]
        action_capability_ids: []
        semantic_policy:
          private.shared: {trust_class: trusted-family, disclose: [shared]}
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

Action rules and every `action_capability_ids` list are intentionally empty in
the Slice A deployment configuration. The existing exact-argument enforcement
remains regression-tested, but no new action is activated by this slice. A
later action slice must add a final-handler live audience revalidation seam
before any group-capable action can become available. If a later approved slice
uses `action_rules`, that list must remain nested at
`juno_kite_trusted_principal.policy.action_rules`; a top-level list is ignored.

Aliases, missing defaults, extra keys, changed destinations/content, wildcard
rules, a second use, and stale turn/policy bindings deny. Action-capable Kite
toolsets should remain disabled until the deny-path tests and an operator canary
pass for the deployed configuration.

Audit Kite's enabled plugin inventory before activation. The standard hook
manager uses the first non-empty `transform_llm_output` result, so no other
enabled hook may return transformed output for this A2A lane. Request or
execution middleware and later `pre_tool_call` hooks may still transform their
ordinary payloads, but any change to an exact authorized mutation is rechecked
and vetoed by `pre_tool_dispatch` immediately before the registry handler. The
final hook receives an isolated argument snapshot and cannot mutate the real
handler payload.

## Enable, health, reload, and rollback

Before enabling, run the focused and regression commands listed in the frozen
contract with a temporary `HERMES_HOME`. Then perform these checks without a
private provider or production action:

The Juno gateway fence activates only when this root configuration block has
`version: 2`, `enabled: true`, `mode: juno`, `profile: juno`, a non-empty exact
WhatsApp group allowlist, and the plugin is enabled in the dedicated,
non-multiplex Juno process. The ordinary WhatsApp adapter must run in `bot`
mode. This activation installs only the adapter's in-process roster/fence
producer before bridge connect; it does not start or publish the historical
private-read service.

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
   is rejected before agent dispatch. Run the checked-in provider-free canary
   from the repository root:

   ```bash
   python -m plugins.juno_kite_trusted_principal.synthetic_canary
   ```

   The helper creates a temporary `HOME`, `HERMES_HOME`, three synthetic HMAC
   keys, and the literal non-production bearer
   `synthetic-juno-bearer-not-a-production-secret`; starts Hermes's real A2A
   adapter on an ephemeral `127.0.0.1` port; and removes the adapter, mapping
   DB, and temporary directory in `finally`. It loads no model or provider and
   registers only an in-process synthetic mutation handler whose expected
   effect count is zero.

   These are the exact HTTP request classes sent by the helper (`<port>`,
   `<signed-request>`, and `<issued-context>` are generated synthetic values):

   - Health: `GET http://127.0.0.1:<port>/health`, header
     `Accept: application/json`, no body. Expect HTTP `200`, JSON object with
     `status: "ok"`, and at most 16,384 response bytes.
   - Wrong bearer: `POST http://127.0.0.1:<port>/`, headers
     `Content-Type: application/json`, `A2A-Version: 1.0`, and
     `Authorization: Bearer synthetic-wrong-bearer`, with body:

     ```json
     {"jsonrpc":"2.0","id":"wrong-bearer","method":"SendMessage","params":{"message":{"role":"ROLE_USER","parts":[{"text":"synthetic wrong bearer body","mediaType":"text/plain"}],"messageId":"<generated>","contextId":"canary-wrong-bearer"}}}
     ```

     Expect HTTP `401`, a bounded JSON-RPC `error` object, and no handler
     dispatch.
   - Authenticated Juno: the same endpoint/method and content headers, with
     `Authorization: Bearer synthetic-juno-bearer-not-a-production-secret` and
     body:

     ```json
     {"jsonrpc":"2.0","id":"<generated>","method":"SendMessage","params":{"message":{"role":"ROLE_USER","parts":[{"text":"<opaque-audit-guard>\nJUNO_KITE_REQUEST_V2 <signed-request>","mediaType":"text/plain"}],"messageId":"<generated>","contextId":"<issued-context>"}}}
     ```

     Expect HTTP `200`, a completed A2A task, a
     `JUNO_KITE_RESPONSE_V2` HMAC envelope no larger than 16,384 bytes, and the
     exact minimized answer `synthetic bounded answer` after Juno verifies it.
   - Wrong context: resend a freshly issued signed request with only the A2A
     message `contextId` changed to `<issued-context>-changed`. Expect HTTP
     `200` and a bounded signed envelope containing `"denied":true`.
   - Unknown tool: send a fresh authenticated signed request whose bounded
     question is `synthetic unknown tool`. The provider-free Kite handler calls
     `pre_tool_call` for literal `synthetic_unknown_tool`; expect a block and a
     verified minimized answer `unknown tool denied`.
   - Changed action argument: send a fresh authenticated signed request whose
     bounded question is `synthetic changed action`. The synthetic exact rule
     authorizes `{"target":"fixture","value":"approved"}`; a later standard
     hook changes only `value` before the real registry handler boundary.
     Expect the final dispatch veto, answer `changed action denied`, and
     `handler effects=0`.

   Every successful line begins with `PASS`; a mismatch raises and exits
   nonzero. Do not substitute a real bearer, provider, profile, private value,
   or action destination.
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
The dedicated v2 activation path neither reads nor changes that flag. Removing
the plugin from Juno's enabled list and restarting Juno also removes the
ordinary adapter fence authority; no legacy private-read host is revived.
