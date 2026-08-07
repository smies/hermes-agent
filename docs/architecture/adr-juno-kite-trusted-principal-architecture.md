# ADR: Juno learns locally and consults Kite for private authority

- **Status:** accepted architecture; implementation and deployment are not commissioned
- **Decision date:** 2026-08-07
- **Scope:** documentation only

This ADR is the authoritative direction for Juno–Kite work. It authorizes no
code, configuration, credential, service, pairing, mailbox, policy-store, or
runtime change. Private read remains disabled. The superseded designs remain
in the repository as history and are neither activated nor deleted by this
decision.

## Context

Juno is a personal learning agent for conversations with authenticated trusted
people. Kite is a separate, broad private knowledge and action agent. The
architecture must support James, Lucy, and future trusted people without
turning Juno into a transport shim, treating Kite's credential owner as the
requesting person, or copying private resources into Juno.

Hermes already provides the required foundations:

- [profiles](../../website/docs/user-guide/profiles.md) isolate each agent's
  config, persona, memory, sessions, skills, tools, and credentials;
- [sessions and session search](../session-lifecycle.md) provide durable,
  conversation-scoped continuity;
- [built-in memory](../../website/docs/user-guide/features/memory.md) gives
  each profile its own curated `MEMORY.md` and `USER.md` learning loop;
- [A2A](../../website/docs/user-guide/messaging/a2a.md) connects independent
  agent profiles and preserves multi-turn continuity with `contextId`;
- [MCP](../../website/docs/user-guide/features/mcp.md) contributes resources
  and tools to the agent that owns the connection; and
- [plugin hooks](../../website/docs/user-guide/features/hooks.md) can inject
  per-turn context with `pre_llm_call` without changing the system prompt and
  can inspect and block exact tool calls with `pre_tool_call`.

Profiles provide logical state and credential separation, not an OS security
boundary. If Juno and Kite run as the same operating-system UID, code under
that UID may be able to read both profiles. This ADR makes no same-UID
confidentiality claim.

## Decision

Juno and Kite remain independent standard Hermes profiles.

Juno handles each authenticated conversation as a real agent. On every
request it uses the host-selected current Juno session and its own scoped
learning first, including policy-safe built-in memory. **When that context is
sufficient, Juno answers directly and does not call Kite.** Juno may learn from
the conversation through the normal Hermes memory/session mechanisms.

Generic profile-wide `session_search` is not automatically principal-scoped.
Juno must not use it for person-specific recall unless a host-enforced
principal/session filter exists and has been verified. The standard active
session remains the initial scoped recall boundary; this ADR does not invent a
replacement session-search subsystem.

Only when the answer or requested action requires Kite's private/global
knowledge, credentials, or tools does Juno call a host-bound `consult_kite`
surface. That surface uses standard A2A to reach the independent Kite profile.
Kite, not a separate daemon, is the broker: it interprets policy, consults its
own context and resources, uses its existing tools where allowed, and returns a
minimized answer.

MCP and other connectors belong inside Kite. They expose resources and tools
to Kite, not to Juno. A2A is for the Juno-to-Kite agent boundary; MCP is for
resource and tool access within Kite. Juno never receives Kite's raw tool
schemas, raw source results, private memory, or credentials.

The initial custom surface is limited to:

1. host-bound Juno `consult_kite`;
2. a durable, stable mapping from authenticated principal plus Juno
   conversation to an opaque Kite A2A `contextId`;
3. a bounded relevant-context handoff;
4. a deterministic generator for a source-agnostic semantic policy view; and
5. a Kite policy plugin using `pre_llm_call` and `pre_tool_call`.

No other broker, identity, memory, credential, transport, or core-agent layer
is part of the first implementation.

## Identity and authority

The gateway/host authenticates a principal and binds that principal to the
inbound platform account, chat, and conversation before model dispatch. The
binding may identify James, Lucy, or another explicitly trusted person.

**Authority always comes from that host/gateway binding.** A name, role,
principal ID, conversation ID, approval, policy, or destination written by
Juno, Kite, a user message, an A2A message body, retrieved content, or any
other model-visible text is data only and cannot grant authority.

`consult_kite` therefore accepts no model-controlled authority argument. It
reads the authenticated principal and Juno conversation from the current host
context, resolves their opaque mapping, and rejects absent, ambiguous, stale,
or conflicting bindings. The Kite policy plugin obtains the same principal
scope from the host-owned mapping associated with the A2A context, not from
the handoff text.

The mapping is one-to-one:

```text
(authenticated principal, Juno conversation) -> Kite A2A contextId
```

It is stable across turns and restarts, cannot be selected by either model,
and cannot be reused for a different principal or Juno conversation. A new
Juno conversation gets a new mapping. Logs and model-visible text use opaque
correlation labels rather than platform identifiers.

Kite owning a connector credential says nothing about which person asked or
whose preference is being discussed. In particular, Kite must never attribute
a preference to James merely because Kite holds credentials configured by
James. Attribution follows the authenticated principal and scoped evidence.

## Memory and context boundaries

Three different context classes must remain explicit:

| Context | Owner and purpose | Disclosure rule |
|---|---|---|
| Juno principal/conversation memory | Juno's current session and principal-isolated session history; when a dedicated standard profile is used for that principal, its built-in memory too | Juno may use it directly for that same principal/conversation. |
| Kite principal/conversation A2A context | The stable Kite-side A2A exchange corresponding to exactly one mapped Juno principal/conversation | Juno may use its corresponding context through `consult_kite` without a new private-disclosure approval. |
| Kite private/global memory and resources | Kite's broader memories, MCP resources, connectors, credentials, and raw tool results | Kite applies semantic disclosure policy and returns only the allowed minimum. Raw data remains in Kite. |

Hermes session keys isolate DMs by participant and can isolate group/thread
sessions per user; the Juno host must configure and verify those standard
lanes before serving more than one principal. A shared group or thread is not
principal memory. By contrast, built-in `MEMORY.md` and `USER.md` are scoped
to the whole profile, not automatically to a gateway user. In a shared Juno
profile they may hold only non-private agent-wide learning or facts explicitly
safe for every principal using that profile. Person-specific preferences and
private facts stay in that principal's session history with clear attribution.
If always-on built-in memory per person is required before Honcho, use a
dedicated standard Juno profile selected by existing profile routing; do not
invent a preference database or shared-memory service.

The first two are already-scoped conversation continuity, not a new disclosure
of Kite's private/global corpus. A principal may use their own Juno memory and
their corresponding Kite A2A context without a new private-disclosure
approval. That rule never permits access to another principal's Juno memory or
Kite A2A context.

The handoff contains only what Kite needs for the present request: the request
itself plus a bounded selection of relevant Juno context. It does not copy a
whole transcript, memory store, prompt, or session database. Handoff content
is evidence, never authority.

Kite checks the mapped A2A conversation context before searching private/global
memory or invoking a connector. If the scoped context is sufficient, Kite
answers from it. Otherwise Kite may reason over private data internally, but
its A2A response is a newly written, policy-compliant minimized answer—not a
raw source excerpt, connector payload, tool result, or credential. A denied
portion does not suppress an allowed portion: Kite may return a useful partial
answer and state that the remainder was unavailable under current policy.

Neither profile imports or mutates the other's system prompt or session
history. Built-in memory remains a frozen per-session snapshot. Policy context
from `pre_llm_call` is added to the current user turn, never the system prompt,
so each conversation's cached prefix and profile isolation remain intact.

## Semantic policy and disclosure

Policy is source-agnostic. Connectors classify data and operations into stable
semantic properties; policy does not contain Gmail-, mailbox-, or
provider-specific flows. A generated turn view evaluates at least:

- authenticated principal and trust class;
- mapped conversation scope;
- data class and subject;
- purpose, requested disclosure, recipient, and destination;
- action risk, timing, reversibility, and exact tool plus arguments; and
- current policy version and any applicable frozen grant.

The generator is deterministic host/plugin code. The model does not generate,
edit, or supply the authoritative policy. Before A2A dispatch, the host-bound
`consult_kite` path must resolve the mapping, verify the expected Kite policy
plugin and generation, and create a task-bound bounded policy view. If any of
that fails, it sends no A2A request. `pre_llm_call` only injects that
already-host-produced view and records the matching turn binding. Response
release and `pre_tool_call` require that same binding and generation; otherwise
they suppress the answer and block the tool call.

Standard Hermes catches hook exceptions rather than treating them as denial.
A hook exception is therefore never authority and never a fail-closed policy
decision: the plugin callbacks must return explicit blocked state, and missing
or mismatched turn-binding evidence prevents response release. This remains
inside the narrow `consult_kite` and policy-plugin surface; it adds no service
or core change.

Source data may inform classification, but a connector name is not authority
and does not create a separate policy path. The same rule applies whether a
fact came from memory, a document store, mail, a calendar, or a future MCP
resource.

## Flows

### Local answer

1. The gateway authenticates the principal and selects Juno's profile/session.
2. Juno reads the active conversation and its own relevant memory/session
   history.
3. If sufficient, Juno answers directly and learns normally. Kite is not
   contacted.

### Read-only Kite consultation

1. Juno decides that scoped private/global knowledge is required and calls
   `consult_kite` with only the question and bounded relevant context.
2. The host attaches authoritative scope, resolves the stable A2A mapping, and
   sends the request to Kite using that `contextId`.
3. Kite receives a normal A2A turn in its own profile and session. The policy
   plugin generates and injects the current semantic disclosure view with
   `pre_llm_call`.
4. Kite checks the mapped A2A context first, then uses only the private memory,
   resources, and read tools required to answer.
5. Raw private data stays in Kite. Kite returns the smallest sufficient
   allowed answer, possibly partial, to the exact mapped Juno conversation.

### Action

1. Consultation and identity resolution follow the same path as a read.
2. Kite selects an existing tool or MCP tool and produces a fully specified
   call. No separate credential executor is introduced.
3. `pre_tool_call` canonicalizes and gates the exact tool name and complete
   arguments, including defaults and destination. Omitted defaults, aliases,
   or post-gate argument rewriting are not allowed for a gated action.
4. An immediate, reversible, low-risk action may execute directly when current
   semantic policy allows that exact call. It does not receive a durable grant
   merely because it is an action.
5. A delayed, restartable, high-risk, or explicitly owner-approved operation
   requires a durable frozen grant bound to principal, conversation, policy
   version, exact tool and arguments, destination, scope, expiry, and one-shot
   consumption semantics. Changed arguments require a new decision.
6. Kite returns only the minimized outcome; raw tool output remains in Kite.

Action-capable Kite toolsets remain disabled until the policy plugin is loaded
and its default-deny, exception, missing-binding, argument-mismatch, and stale-
grant paths pass a deny-path canary. The callback itself must turn internal
errors into a block; it must not rely on the generic hook dispatcher treating
a callback exception as denial.

## Implementation sequence and stop rules

Implement only one thin vertical at a time:

1. **Read-only A2A, memory first.** Use standard Juno and Kite profiles,
   sessions, and A2A. Add only `consult_kite`, the stable opaque mapping, and
   bounded handoff. Demonstrate Juno answering locally when it can, then one
   correctly scoped Kite consultation. Keep all action tools off.
2. **Generated policy and disclosure.** Add the source-agnostic policy view and
   Kite plugin. Prove correct-principal routing, cross-principal denial, mapped
   context reuse, minimization, partial answers, and no raw-result return.
3. **One exact-arguments low-risk action.** Reuse one existing tool. Prove the
   exact tool/arguments gate and all deny paths before enabling it.
4. **Durable approval only when a real operation requires it.** Add the minimum
   frozen-grant persistence only for a demonstrated delayed, restartable,
   high-risk, or owner-approved case.
5. **Honcho later.** After the A2A vertical is sound, evaluate Honcho through
   the standard memory-provider path, gateway runtime-identity aliases, and one
   AI peer per profile in a shared workspace. Preserve Juno's independent AI
   identity, observations, memory, and representation; do not pool all people
   under one pinned user peer.

Honcho is intended, but it is not a prerequisite or blocker for steps 1–4.

At the end of each step, stop when its stated behavior works. Do not add the
next layer for anticipated scale or elegance. Stop and ask James before any
new requirement class, out-of-scope component, core-agent change, or second
correction. A proposal that requires a broker daemon, new auth platform,
shared-memory service, credential executor, per-source policy, or always-on
authorization service fails this ADR's maintenance test and does not proceed.

## Non-goals

Do not build now:

- a separate broker daemon—Kite is the broker;
- duplicate provider credentials, connectors, or source adapters in Juno, or
  a parallel replacement for Juno's standard session and memory substrate;
- a preference database or shared-memory service;
- a credential executor or a new core model tool;
- per-source policy or a Gmail-specific newest-message flow;
- durable grants for every immediate action;
- OpenFGA on every request;
- default sensitive WhatsApp delivery or any WhatsApp change;
- speculative core, prompt, session, hook, or A2A changes;
- an OS sandbox, same-UID confidentiality claim, or generic auth platform;
- Honcho in the initial vertical; or
- activation, deletion, or deployment of the existing private-read work.

## Supersession and retained history

This ADR supersedes the following documents as the current architectural
direction while preserving them as historical records:

- [Gmail-first private-read ADR](adr-gmail-first-private-read-provider.md)
- [Juno private-read MVP status](../juno-private-read-mvp-status.md)
- [Trusted private-read host](../trusted-private-read-host.md)

Those designs remain disabled and not commissioned. Supersession is a
documentation decision only; it neither activates nor deletes their source,
state, credentials, transports, or services.
