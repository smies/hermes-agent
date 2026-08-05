# ADR: Gmail as Juno's first concrete private-read provider

- **Status:** proposed; implementation and deployment are not authorized
- **Decision revision:** 2026-08-05
- **Revision source commit:** `be72114b7c32501d8c24cddae4d1dac9b8f47825`
- **Revision source tree:** `d062c450ce72c2710cf2c17edcedd877e2fc83cc`
- **Revision source ADR SHA-256:**
  `7b7832be421b86402561d106bf75cd45de376ebdbd004209e2a5ecb372bee731`
- **Reviewed WIP source commit:** `49d78bdc915e9e2c3ff78d7d4a3a7074ddb6ac85`
- **Reviewed WIP source tree:** `c88ba9d705453561678b4e8ba2b501b4ff55a8bd`
- **First reviewed ADR SHA-256:** `d9a413c3a44297ce02ed6e83f01a6f5de61b7be78f9a907677a223210367a700`
- **Audience:** product, security, gateway, policy, and release reviewers

This ADR describes a future implementation. It authorizes no code change,
OAuth consent, mailbox access, OpenFGA provisioning, WhatsApp pairing, bundle
installation, process restart, configuration activation, or private read.

## 1. Product decision

### Exact v1 operation

Juno's first code-owned private-read operation is exactly:

```text
capability ID: gmail.newest_inbox_message.read
Gmail query bytes: in:inbox
fields: sender, to, cc, subject, date, text_body
approval label: Newest Inbox message — selected headers and plain-text body only
```

The field tuple is ordered and immutable. Version 1 calls Gmail
`messages.list` once with the exact query bytes `in:inbox`, `maxResults=1`, and
`includeSpamTrash=false`, then gets the returned message once. It does not
paginate, search a second account, or expose a query or message ID to the
model. The model-visible proposal remains exactly `{capability_id}`.

The current Gmail
[list-messages guide](https://developers.google.com/workspace/gmail/api/guides/list-messages)
states that `messages.list` returns messages in reverse chronological order,
newest first. That provider contract supports the word “newest” for the first
result. Gmail does not promise a snapshot across the list/get sequence;
concurrent mailbox mutation can change the mailbox between calls, so v1 makes
no snapshot or global-total-order claim.

The query is exact Gmail API syntax. Gmail's
[filtering guide](https://developers.google.com/workspace/gmail/api/guides/filtering)
documents differences from Gmail's UI: the API does not perform UI alias
expansion and does not provide thread-wide search. The adapter sends the bytes
`in:inbox` without semantic rewriting. `includeSpamTrash=false` is defense in
depth and is not treated as a substitute for the Inbox query.

One approved operation may output only these canonical fields, in this order:

1. `sender`, from the root Gmail message payload's single `From` MIME header;
2. `to`, from the root Gmail message payload's single `To` MIME header;
3. `cc`, from the root Gmail message payload's single `Cc` MIME header;
4. `subject`, from the root Gmail message payload's single `Subject` MIME
   header;
5. `date`, from the root Gmail message payload's single `Date` MIME header;
   and
6. `text_body`, from exactly one eligible non-attachment `text/plain` leaf.

Header values are message claims, not authenticated identities. Child-part
headers are classification inputs only: they can never populate, replace, or
override an output field. A root header missing from the root payload renders
as the fixed `(not present)` marker even when a child part contains a header of
the same name. Message and thread IDs are ephemeral correlation inputs and are
never output.

### Owner-facing approval poll

The stable label is exactly:

> Newest Inbox message — selected headers and plain-text body only

The challenge is exactly one private, one-to-one owner-DM poll. It is the
single-select `pollCreationMessageV3` variant produced by the code-owned
ordinary approval operation through pinned
`@whiskeysockets/baileys@7.0.0-rc14` and verified in pinned Node contract
tests. Its `selectableCount` is exactly `1`, and its two ordered UTF-8
option-name byte strings are exactly:

1. `Approve`
2. `Deny`

There is one poll creation message and no fallback text message, button,
reaction, or separate control. A group JID, status/broadcast JID, or any
destination other than the exact configured owner DM fails closed.

The poll question is exactly this LF-delimited UTF-8 template, with no leading
or trailing extra line:

```text
Approve one Gmail private read?
Newest Inbox message only.
Return: sender, to, cc, subject, date, text_body.
Exclude: attachments, HTML, spam, trash, additional messages.
Request: {task_display_id}
Generation: {challenge_generation}
Expires: {expiry_rfc3339_utc}
```

The code-owned task display ID is 1 to 64 ASCII bytes matching
`[A-Za-z0-9_-]+`. Challenge generation is the shortest unsigned decimal
encoding of an integer from 1 through `2^64-1`, with no leading zero. Expiry is
the canonical 20-byte RFC 3339 UTC form `YYYY-MM-DDTHH:MM:SSZ`. Each value is
parsed and rendered from its typed store field rather than interpolated from
untrusted text. The complete rendered question must be at most 512 UTF-8
bytes. Labels, punctuation, spaces, field order, and LF delimiters are fixed.
The notification envelope separately contains the exact ordinary destination
binding without displaying a private Gmail identity.

For every attempt, the gateway private host computes a domain-separated HMAC over
the complete
rendered question, the exact ordered option bytes, `selectableCount=1`, the
`pollCreationMessageV3` variant, the fresh message-secret digest, pre-reserved
provider poll ID, exact destination, and canonical dynamic envelope: task ID,
task display ID, request and challenge generations, exact expiry, destination
binding digest, attempt ID, capability descriptor and stable-label digests,
ordinary bridge/launcher/package identity, adapter instance, account binding,
socket, connection and authority epoch, private-host/coordinator/signing
generation, authenticated provenance version, and template version. The stable
label retains its exact descriptor and HMAC semantics even
though the rendered poll question is the single message shown to the owner.
The challenge-payload digest is bound before send and must appear in correlated
destination-delivery and owner-decision evidence. A digest of only the stable
label or static template is insufficient.

The owner decides only by selecting exactly one option in that exact tracked
poll. Free-form text, model output, aggregated option text, a copied or
forwarded poll, quote, button, or reaction cannot mint a decision.

### Content-free owner outcomes

Ordinary and status surfaces never contain Gmail account, query, message IDs,
headers, body, or other private values. The fixed outcomes are:

- **Approval required:** `Private read awaits your bound Approve or Deny poll
  selection; it expires at {exact time}.` Use the exact tracked poll.
- **Denied:** `Private read denied. No mailbox content was read.` A later
  request starts a new task.
- **Expired:** `Private-read approval expired. No mailbox content was
  returned.` A later request starts a new generation.
- **No match:** `No matching Inbox message was available for this approved
  read.` The operation is consumed; request again if needed.
- **Malformed or no safe plain body:** `The selected message had no safely
  readable plain-text body.` The operation is consumed; no content is shown.
- **Gmail, account, or scope failure:** `Private read failed at the Gmail
  account boundary.` The feature remains closed until healthy.
- **Policy failure:** `Private read was not authorized by current policy.` No
  Gmail read occurs at the denied stage.
- **Sensitive pre-submit failure:** `Sensitive delivery did not start.` No
  send occurred; store policy decides a fresh attempt.
- **Ambiguous sensitive post-submit outcome:** `Sensitive delivery outcome is
  unknown; this authorization was consumed.` Never retry the same
  authorization or message.
- **Confirmed sensitive delivery:** `Sensitive delivery was confirmed.` This
  means exact delivery/read/played evidence, not human interpretation.

`Confirmed sensitive delivery` requires the existing exact correlated
`DELIVERY_ACK`, `READ`, or `PLAYED` sensitive-transport evidence. Ordinary
approval and resolution destination-delivery evidence is separate and never
upgrades to sensitive-delivery evidence. Neither evidence class proves human
understanding or approval.

### Product boundary

The operation is default-off, single-account, one-shot, owner-approved,
task-bound, and Juno-only. Private output goes only through a separately paired
sensitive WhatsApp transport. It never returns to the model, ordinary
WhatsApp, relay, tool result, session, memory, or audit store.

## 2. Status and evidence

Evidence captured read-only on 2026-08-05 is separated by kind:

- **Source proof:** the production checkout
  `/Users/james/.hermes/hermes-agent` was clean at commit
  `b1933e49691a9408d43b75d69a2b3e1df97d9914`, tree
  `10bd5cf8b983435a346d2e477868719abf04194b`. The gateway, ordinary
  WhatsApp, authorization, private-read, and sensitive-delivery foundation
  source is present in that checkout. In that source, private-read production
  composition remains dormant/unavailable by reviewed source construction.
  Source presence does not prove runtime activation or deployment.
- **Process proof:** launchd label `ai.hermes.gateway` had observed PID `46046`
  running
  `/Users/james/.hermes/hermes-agent/venv/bin/python -m hermes_cli.main gateway run --replace`,
  with process start time `Tue Aug 4 14:14:38 2026`. The launch command has no
  explicit profile flag. This proves only the clean checkout OID/tree and one
  observed running gateway command. It does not prove the process's loaded
  source OID, runtime profile or configuration, or activation/deployment of
  the ordinary WhatsApp, authorization, private-read, or sensitive-delivery
  subsystems. No such fact may be inferred from source presence or the command,
  and the live profile must not be inferred as `juno`.
- **Absent or unverified active state:** no evidence established an active
  Gmail private-read composition, dedicated OAuth client/token, exact granted
  scope, Gmail account binding, OpenFGA service/model/policy, root-owned
  dedicated runtime bundles, paired sensitive session, or published
  Juno-only tool.
- **Externally asserted facts:** any claim about provider-console state,
  account ownership, launchd environment, connector deployment, or live
  transport pairing that is not in the source/process proof above remains an
  operator assertion until separately evidenced.

The source checkpoint is an unaccepted design draft, not an implementation
PASS. In particular,
[`compose_trusted_private_read_services()`](../../gateway/trusted_private_read_host.py)
returns `None` in the reviewed source, so enabled configuration cannot produce
a working private-read composition. The proposed changes below replace that
dormant boundary only after implementation review.

## 3. Privacy and threat contract

### Owner-selected process and trust boundary

The owner selected **Option 2** on 2026-08-05 after reviewing the stronger
alternative of separate service UIDs and its operational cost. The final
architecture runs three independently supervised processes under the existing
gateway macOS UID:

1. one **dedicated Juno gateway/private-host process** owns the immutable
   capability registry, generic authorization task store, HMAC and commit-
   signing private keys, Gmail OAuth/token files, Gmail HTTP/MIME provider,
   OpenFGA client, worker, publication record, approval/sensitive-delivery
   orchestration, and transient Gmail plaintext;
2. one **ordinary Juno WhatsApp bridge process** owns and reuses the complete
   ordinary Baileys session in place and handles ordinary chat plus the
   authority-only approval protocol; and
3. one **sensitive WhatsApp bridge process** owns the separately provisioned
   sensitive account/session/socket/dependency graph and receives private
   plaintext only through the dedicated sensitive-delivery protocol.

Ordinary and sensitive identities are distinct and immutable. Their processes,
sessions, authentication directories, sockets, IPC namespaces, queues, package
roots, dependency graphs, manifests, and launch records remain separate; the
two bundles never import or resolve one another. Sharing a UID does not collapse
those application boundaries, but this ADR does not claim they provide OS
confidentiality isolation.

The existing complete ordinary authorization directory
`/Users/james/.hermes/profiles/juno/whatsapp/session` remains owner-only and is
reused in place. It is never copied, moved, split, ownership-transferred,
ACL-changed, or reduced to `creds.json`. No new service UID or session ownership
migration is part of Option 2. The sensitive session remains separate and
pairing-gated; pairing uses an alphanumeric phone-link code only and never a QR
code.

Production composition is concrete, code-owned, and gateway-owned.
`compose_trusted_private_read_services()` constructs only the built-in typed
Gmail, OpenFGA, store, approval, and sensitive adapters from the dedicated
closed decision record and exact runtime objects. It never accepts a callback,
URL, command, import path, plugin factory, environment-selected provider, or
arbitrary implementation.

### Explicit broad TCB and owner risk acceptance

The v1 trusted computing base includes the gateway UID; every process and code
component running as that UID, including anything capable of reading its files
or process-memory interfaces; all code loaded into the dedicated Juno gateway/
private host; and the complete ordinary and sensitive bridge processes. Owner-
only modes protect against other OS users, not malicious or compromised code
running as the gateway UID.

Accordingly, v1 makes no OS-confidentiality claim against another same-UID
process, same-process memory inspection, debugger attachment, credential-file
reads, or a compromised TCB component. Root/kernel compromise and compromise
of any same-UID TCB process are outside v1 guarantees. Profile files, plugin
directories, tool registries, credentials, sessions, stores, and integrity
keys remain same-UID-readable or writable in principle. Hashes, manifests,
HMACs, and seals detect accidental drift or corruption within this TCB; they
are not claimed to defeat malicious same-UID code that can also read or replace
state and keys.

The owner explicitly accepts this residual risk in choosing Option 2 on
2026-08-05. Separate service UIDs or a sandboxed private service remain the
stronger future alternative and require a new ADR plus separate deployment
approval.

The guarantees that remain in scope are no deliberate private-data flow into
model, tool, session, ordinary-message, log, or storage surfaces; exact
authorization and transport evidence; bounded lifetime; root-owned executable
integrity; strict Juno capability lockdown; deterministic private rendering;
and synthetic/adversarial verification.

The exact authenticated requester binding, dedicated Gmail Desktop OAuth
client/grant and expected account, signed OpenFGA policy state, and exact
bundle/process generations remain authority inputs. Display names, aliases,
ambient profiles, global Google credentials, self-reports, relay claims,
model text, and environment-selected accounts never are. Google compromise is
also outside v1.

The ordinary gateway/model/tool layer receives no sensitive-delivery endpoint.
The in-process private host writes private plaintext only through its inherited
private endpoint; the root-owned supervisor passes the peer endpoint only to
the sensitive bridge. No ordinary gateway object receives an endpoint
reference. The sensitive process never returns plaintext, rendered content, or
provider error text, only fixed authenticated delivery evidence.
The approval-authority channel and ordinary generic chat channel are distinct:
generic chat has no approval opcodes, while approval has no generic text-send
or private-result operation beyond the exact content-free challenge and
resolution schemas.

### Four data classes

The implementation distinguishes four boundaries:

1. **Bounded incidental receipt.** Gmail REST can return documented metadata
   and base64url inline MIME body data not needed by v1. Such bytes may exist
   transiently inside the Google TLS, HTTP client, bounded response, and closed
   parser boundary. Partial-response selectors reduce this receipt but cannot
   filter MIME array elements by media type.
2. **Eligible decoded data.** Only the five named header values and exactly one
   bounded, non-attachment `text/plain` inline body are eligible for decoding
   and canonicalization. Ineligible `body.data` is never decoded.
3. **Allowlisted DTO and output.** Only `sender`, `to`, `cc`, `subject`, `date`,
   and `text_body` may enter `GmailMessageReadDto` or the deterministic
   sensitive renderer.
4. **Forbidden handling.** Incidental or eligible private values may never be
   emitted outside the private path, persisted, logged, traced, diagnosed,
   indexed, put in a model/tool/session/task/policy/audit object, remotely
   fetched, or used to take an action other than the one approved sensitive
   delivery.

This is intentionally not a claim that Gmail never returns forbidden fields.
The fixed selectors exclude top-level label IDs, snippet, history ID, internal
date, size estimate, profile totals, and list estimates, but bounded incidental
HTML/attachment metadata or encoded inline body data can still arrive in MIME
arrays.

### Forbidden emission, persistence, decoding, fetch, action, and diagnostics

Version 1 must never:

- fetch an `attachmentId`, decode attachment, HTML, `message/rfc822`, or other
  ineligible body data, render HTML, execute scripts/styles, load pixels/links,
  or perform any remote content fetch;
- emit or persist labels, snippets, history, internal dates, size estimates,
  mailbox totals, MIME structure, unlisted headers, Gmail IDs, attachment
  metadata, or incidental encoded data;
- inspect a second result, follow a page token, read spam/trash, read a second
  account, or perform Gmail send/modify/delete/draft/import/insert/archive/
  mark/label/settings/contact/history operations;
- use private content for a model transformation, decision, redaction,
  summarization, authorization, diagnosis, retry decision, or metric; or
- place credentials, query bytes, account identity, IDs, headers, body, HTTP
  objects, or provider/parser exception details in prompts, model messages,
  tool results, ordinary notifications, logs, traces, metrics, audits,
  OpenFGA, SQLite/WAL/journal, sessions, history, memory, checkpoints,
  trajectories, environment, argv, files, caches, indexes, replay data,
  exception graphs, live-task descriptions, or completed task results.

### Exact resource bounds

The following are code maxima; the dedicated decision record may only reduce
them using its integer units. The effective values are descriptor-bound.
Crossing a cap fails rather than truncating silently.

- Query: exactly the UTF-8 bytes `in:inbox`; maximum schema allowance 512
  bytes, one non-empty line, no NUL/control/DEL or surrounding whitespace.
- Provider message/thread ID: 256 ASCII bytes each.
- URL: fixed HTTPS authority and code-owned paths, at most 2 KiB after encoding.
- Request/response headers: at most 32, 8 KiB aggregate, 2 KiB each.
- OAuth response: 32 KiB; profile and list response: 64 KiB each; message get:
  256 KiB; OpenFGA response: 4 KiB.
- JSON: strict UTF-8, duplicate keys rejected, depth 32, 256 aggregate entries,
  signed 64-bit integers, closed documented types.
- MIME: depth 8, 32 total parts, 64 headers per part, 64-byte header names,
  2,048-byte decoded header values, 8 KiB aggregate allowlisted header text.
- Candidate body data: 64 KiB aggregate encoded inline text, 16 KiB aggregate
  decoded eligible bytes, exactly one eligible plain leaf, and at most 3,072
  UTF-8 bytes after CRLF-to-LF normalization.
- Rendered result: at most 4,096 UTF-8 bytes including fixed labels/separators.
- Network: connect 2 seconds, write 2, read inactivity 5, pool 1, and an outer
  true-total deadline of 8 seconds per OAuth/Gmail/OpenFGA request. Complete
  private read has a 20-second outer deadline. HTTPX timeouts alone are not
  treated as end-to-end deadlines.
- Redirects: none. Any 3xx fails.

Exact response-byte caps are enforced while streaming and before full response
allocation. After that bounded JSON byte allocation, the duplicate-rejecting
closed parser enforces object, nesting, aggregate-entry, MIME depth/part/header,
encoded-candidate, and decoded-candidate limits. It applies all structural
limits before decoding any body data. It does not claim to enforce MIME limits
before network or JSON allocation.

Google uses reviewed CA validation. OpenFGA alone uses the code-fixed loopback
HTTP endpoint. All clients disable redirects, proxy/environment trust,
`.netrc`, ambient credentials, and provider-controlled authorities.

### Honest memory guarantee

V1 guarantees bounded logical reachability and deliberate data-flow exclusion,
not UID isolation or physical zeroization. Gmail content and tokens exist only
inside reviewed private frames in the dedicated Juno gateway/private host until
the fixed rendered bytes cross the authenticated sensitive-delivery channel.
They have the shortest practical lifetimes;
references are released explicitly in `finally` paths; controlled mutable
buffers are wiped where the application truly owns them. The sensitive bridge
holds only the bytes required for the one send. No application persistence,
logs, traces, model/tool/session/history/audit/policy/task content, or retained
task results are permitted.

V1 does not claim that immutable Python `bytes`/`str`, HTTPX request/response
objects, TLS buffers, exception allocator storage, CPython allocator copies,
or immutable Node buffers are physically erased. A memory-forensic attacker
inside the dedicated Juno process is within the private TCB; one inside the
sensitive bridge can observe its bounded delivery plaintext. The model-facing
frames never receive plaintext, but the private host and model-facing gateway
code share a process and TCB. Another same-UID process may technically inspect
memory or owner-only files. A physical-erasure or same-UID-adversary requirement
needs a separate stronger isolation ADR.

`GmailMessageReadDto` is a slots-based class with `repr=False`, a fixed
redacted `__repr__` and `__str__`, and no dataclass `asdict`, pickle, or copy
helpers where feasible. Privacy tests cover `repr(dto)`, `str(dto)`, container
reprs, attempted pickle/copy, and all exception/task surfaces.

### Exception and cancellation hygiene

The gateway private host never calls `raise_for_status()` and never transmits an
HTTPX, OAuth, provider, JSON, MIME, renderer, approval, or sensitive-send
exception across IPC. A private inner async frame owns request, response,
token, body, parser, DTO, and render references. It catches every failure,
manually maps the HTTP status and failure class to a closed non-private code,
closes streams, releases all request/response/token/body references, wipes
controllable buffers, and completes bounded mandatory cleanup.

Only after the private exception frame has exited does an outer wrapper raise
a fresh fixed `PrivateReadProviderFailure(code)` from `None`. Public error text
is selected from a closed constant map and contains no upstream text.

For cancellation or another `BaseException`, the inner frame records only a
non-private control-flow kind, completes mandatory shielded bounded cleanup,
exits the exception frame, and then recreates cancellation/control flow from
outside it without retaining or re-raising the original exception graph. A
fresh `asyncio.CancelledError()` or fixed control exception is raised from
`None`. Cleanup failure permanently revokes service health and returns only a
fixed content-free diagnostic.

Tests recursively traverse exception cause, context and tracebacks and inspect
traceback locals, suspended/completed coroutine frames, HTTPX request/response
objects, live tasks, task callbacks, and completed task results. Sentinels must
be absent after success, every mapped failure, cancellation, and shutdown.

## 4. Requester, discovery, and durable capability identity

### Closed requester scope

The dedicated decision record contains one closed `requester` object with
exactly `gateway_profile`, `agent_identity`, `platform`,
`ordinary_account_binding`, `owner_sender`, `source_chat`,
`source_thread_sentinel`, and `authenticated_provenance_version`.
`gateway_profile` is exactly `juno` and `platform` is exactly `whatsapp`; the
other strings are separately reviewed opaque deployment identities.

Unknown or missing requester keys fail parsing. Every value is sealed into the
composition and requester-scope digest. The gateway checks all eight values at
authenticated event bind and again when durably creating the task. Wrong
profile, agent, platform, account, sender, chat, thread sentinel, provenance,
or generation fails before model invocation, tool invocation, task mutation,
or authorization mutation. No event-global or ambient profile may substitute.

### Dedicated Juno process and capability lockdown

The dedicated gateway process launches with the exact `juno` profile and an
exact sealed profile/HERMES_HOME generation. It may not host, switch to, or
load any other profile in the same process. Existing evidence does not prove
that the observed gateway process used Juno; deployment must prove the exact
future executable, argv, environment, profile, HERMES_HOME generation, and
loaded source/bundle identity.

Before model/provider/client initialization or credential/store access,
startup computes a canonical `JunoCapabilityManifest` from code-owned constants
and the sealed profile. The only model-callable v1 tools are:

1. the service-gated `private_read_request` tool with exact
   `{capability_id}` schema; and
2. optionally the existing code-owned query-only `web_search` tool, but only
   if review proves that its exact implementation exposes no URL, local-network
   target, file, browser, code, shell, credential, arbitrary HTTP backend, or
   backend-selection parameter.

If the second predicate is not proved, v1 starts with only
`private_read_request` and answers ordinary questions from model knowledge.
The ordinary WhatsApp response path is gateway-owned output delivery, not a
model-callable send tool. Approval and sensitive delivery are private runtime
operations unreachable through model tool dispatch.

The manifest explicitly forbids, and startup plus per-call tests prove absent:

- terminal, shell, process, PTY, `execute_code`, Python/Jupyter, and coding-
  agent tools;
- file read/write/search/patch, local URLs, attachments, and filesystem-backed
  media tools;
- browser, desktop/computer-use, Apple automation, OCR/document tools, and
  arbitrary HTTP fetch/extract;
- `send_message`, email/Google Workspace, session search, memory mutation,
  cron, delegation/subagents, skill creation/editing, and skill scripts;
- Home Assistant, messaging side-effect tools, arbitrary MCP/catalog servers,
  dynamic plugins, plugin-provided tools, user-installed hooks, runtime tool
  discovery, and profile crossover; and
- model-authored commands, import paths, callbacks, URLs, Gmail queries,
  account identifiers, or provider choices.

The manifest seals the exact tool-definition bytes, names, schemas, handler
identities, registry sources, plugin and hook list, MCP list, model identity,
profile identity/instruction digest, and profile/HERMES_HOME generation. These
are attested before credentials/store access; when a genuinely new conversation
generation captures `PrivateReadConversationCapability`; before every model
call; before tool planning and execution; and immediately before private claim
and read.

Any extra, missing, or replaced tool, plugin, MCP server, hook, handler, schema,
profile, model, registry source, or generation synchronously unpublishes
private-read, terminalizes affected pre-side-effect tasks, and fails the
dedicated Juno process closed. The model cannot enable tools or alter the
allowlist. Agent eviction or rebuild reloads the same persisted content-free
conversation capability and manifest identity; it never recaptures newer
availability.

Because manifest inputs and seal keys are within the broad same-UID TCB, these
checks reliably detect accidental drift and reviewed-state mismatch but do not
claim resistance to malicious same-UID code able to replace inputs and keys.

### Cache-stable discovery

Before a new Juno conversation begins, the service-gated private-read tool
schema is materialized from the immutable reviewed operation registry. Its
capability property is an exact enum containing only
`gmail.newest_inbox_message.read`; its description says, without private data,
that the capability requests owner approval to read selected fields from the
newest Inbox message. The tool schema and Juno profile instructions contain no
query plaintext or Gmail account identity.

The materialized schema and Juno profile instruction bytes remain unchanged
for the lifetime of that conversation. Enabling, disabling, replacing a
descriptor, or publishing a new runtime never mutates an existing
conversation's tool list or system prompt. Activation requires a fresh Juno
conversation/session generation after successful service publication. Existing
conversations remain unavailable, preserving prompt-cache identity.

The gateway publishes this one content-free tool only after in-process private-
host initialization verifies the exact root bundle, decision record, runtime
objects, Juno capability manifest, schema, requester, and publication
generation. A proposal contains only the capability ID, an opaque bridge-
minted one-use inbound-turn grant, exact session/conversation generation, and
fixed content-free correlation. The ordinary bridge mints that grant from the
authenticated owner inbound turn; the private host verifies and atomically
consumes it. Model-facing code cannot mint, inspect, extend, or replay a grant.
The private host returns only fixed content-free task and terminal outcome
states. Gmail output never enters a tool result or model-facing frame.

At creation of a genuinely new gateway session/conversation generation, the
gateway atomically captures an immutable, content-free
`PrivateReadConversationCapability` together with the schema bytes. It
contains the exact gateway session generation, profile/requester binding,
private-host/publication generation, root bundle/process identity,
`JunoCapabilityManifest` digest and allowlist/plugin/model/profile identity,
schema digest and bytes, terminal-handler capability identity, and explicit
presence/absence state. The binding is persisted with session-generation
metadata. Agent eviction, process reconstruction, or gateway restart reloads
that binding; it never recaptures live availability for an existing session.

A session born absent remains absent. A session born with publication
generation G may execute only while the current publication is exactly G with
identical process, bundle, Juno manifest, schema, requester, and terminal
capability identity.
Removal or replacement fails closed and never falls forward. A new publication
can become available only to a genuinely new session generation. Direct tool
execution and deferred Tool Search definition/scope planning use only the
session-bound capability and the exact-current equality/revocation check; they
never resolve a current or newer runtime at call time.

Tests prove: absent service means absent schema; a healthy published Juno
generation gets the exact one-value enum and exact non-private purpose; other
profiles get no schema; absent and old generations do not gain it after
restart, eviction, or service replacement; revoked generations fail closed;
and capability/schema/instruction bytes are stable across turns.

### Canonical descriptor and fingerprints

The immutable operation registry contains one closed descriptor. Its canonical
bytes include, or domain-separated HMAC-bind, all of:

- descriptor version, capability ID, operation version, provider kind, and
  adapter implementation identity/version/digest;
- Gmail account-binding HMAC and exact query HMAC for `in:inbox`;
- the ordered field tuple `sender,to,cc,subject,date,text_body`;
- every exact effective read/network/parser/render limit;
- the exact stable approval-label digest, poll-question template/version,
  `pollCreationMessageV3` variant, `selectableCount=1`, ordered option bytes,
  dynamic-field grammar and bounds, and 512-byte rendered-question cap;
- the exact requester-scope digest;
- OpenFGA store, authorization-model, policy and owner-policy-epoch identities,
  plus the requesting agent/model identity required by policy; and
- all identifier-mapping and descriptor-domain versions.

The durable `resource_id`, parameter fingerprint, authorization binding,
request HMAC, and composition seal domain-separately bind the whole descriptor.
Neither Gmail account identity nor query plaintext is stored in a task, audit,
approval message, policy request, schema, prompt, or model context.

The complete rendered challenge-payload digest is separate from the stable
approval-label digest and descriptor digest. Each notification attempt binds
its own dynamic task/generation/expiry/destination bytes to that attempt and to
provider evidence.

Whole-descriptor exact match is mandatory on restart reconciliation, dequeue,
immediately before claim, and immediately before private read. Matching only
capability ID, resource ID, or a subset of fields is forbidden.

### Store-owned descriptor reconciliation

One coordinator-fenced store transaction owns reconciliation. It takes the
current descriptor registry generation and exact coordinator lease, locks the
affected task/attempt rows, preserves the decision and resolution record, and
atomically refreshes the mutable-state HMAC and audit-chain head/count for
every mutation. Its status rules are:

- A pre-side-effect pending or approval task becomes terminal
  `descriptor_mismatch`. Unstarted notification attempts become superseded;
  definite pre-submit failures remain failed.
- A `claimed` task or any post-read uncertainty becomes terminal
  `failed_consumed`. Send-start-fenced attempts become ambiguous unless exact
  terminal evidence already exists.
- When a decision is recorded and its resolution is pending, the decision
  remains audit-complete and the task terminalizes according to side-effect
  state. The resolution attempt becomes superseded, failed, or ambiguous from
  its own send-start fence.
- A terminal task is unchanged, verified audit repair is forbidden, and its
  existing evidence remains immutable.

No generic `cancel()` transition is reused where its accepted states or reason
codes do not fit. A mismatch can never revive or requeue an approval. Dequeue,
pre-claim, and pre-private-read checks use the same exact descriptor matcher.

## 5. Ordinary approval challenge and resolution

### Same-UID IPC and application separation

Unix peer UID cannot distinguish the gateway/private host, ordinary bridge,
and sensitive bridge because all run as the existing gateway UID. Peer
credentials may be recorded as process evidence but are never claimed as
sufficient confidentiality or authentication among these processes.

The root-owned supervisor creates connected socketpairs before dropping and
execing the exact processes. It passes only each manifest-allowlisted endpoint
file descriptor, closes every other copy, and binds a fresh random channel key
and nonce to the exact bundle, process, start, socket, connection, and authority
epochs. Capabilities are delivered only through already-open inherited file
descriptors, never through filesystem token files, argv, or environment. There
is no discoverable listening path another same-UID process can connect to.

There are exactly three cryptographically independent channels:

1. ordinary approval commands and authority events;
2. ordinary generic chat; and
3. sensitive delivery.

Every protocol is closed-schema, length-bounded, sequence-numbered,
transcript-HMACed, replay-protected, and epoch-bound. The generic chat protocol
has no approval opcodes. The approval protocol has no generic text send or
private-result opcode except exact content-free challenge/resolution payloads.
Only the private-host component receives the plaintext-writing endpoint object
for the sensitive bridge pair; the ordinary gateway/model/tool layer and
ordinary bridge code receive no endpoint or reference. Sensitive responses
contain fixed authenticated evidence only.

This construction prevents accidental cross-channel use and routing through
untrusted model/tool surfaces. A same-UID debugger or process-memory attacker
could extract a channel capability and is inside the explicitly accepted TCB;
the protocol is not represented as protection from malicious same-UID TCB
compromise.

### Exact rc14 destination-delivery contract

`OrdinaryWhatsAppApprovalAuthority` uses dedicated code-owned ordinary
Baileys operations, not generic `SendResult`. V1 challenge and resolution
destinations are the exact configured private one-to-one owner DM. Group and
status destinations fail closed. For that one-to-one destination, the pinned
rc14 bridge observes `messages.update` and accepts only a known status whose
numeric value is at least `DELIVERY_ACK`: exactly `DELIVERY_ACK`, `READ`, or
`PLAYED` where playback is semantically available. The event must correlate to
the exact pre-reserved message ID, destination JID, ordinary account, socket
identity, and connection epoch. The durable evidence is named
`ordinary_destination_delivered` and records the exact accepted signal and
observation time.

These provider-layer events prove delivery, read, or playback at that exact
destination; they do not prove human understanding, intent, or approval.
Pinned rc14 maps receipt type `sender` to `SERVER_ACK`, which can be a
sender-side companion receipt. `SERVER_ACK` is therefore always
non-accepting. Sender-companion echoes, generic send completion, HTTP response,
`SendResult.success`, a locally generated or returned ID, unknown status,
reconnect, timeout, disconnect, or a late event are also non-accepting.

V1 has no group approval notifications. Any future group support requires a
separate security and protocol review and exact participant-scoped
`message-receipt.update` evidence; one-to-one `messages.update` logic may not
be generalized to a group.

The bridge pre-correlates every attempt before send and records:

- notification kind (`approval_challenge` or `approval_resolution`), attempt
  ID, task ID, request/challenge generation, exact payload digest, and expiry;
- provider message ID, exact destination, ordinary adapter instance, account
  binding, socket identity, and connection epoch;
- exact accepted destination status, evidence ID, and observation time; and
- code-owned bridge/launcher/package identity and authenticated event
  provenance/version.

Once the send-start fence is crossed, absence of exact destination evidence is
ambiguous. That attempt and message ID are consumed and never retried. Where
the task permits another challenge, the store creates a new attempt and new
challenge generation, never a replay of the old attempt or message.

The store is the sole attempt-ID allocator. It derives the bounded attempt ID
deterministically as a domain-separated HMAC of task ID, notification kind,
request generation, challenge generation, and monotonically assigned attempt
ordinal. Challenge and resolution kinds use distinct domains; an ID cannot be
reused across a generation or notification kind.

### Challenge state machine

The challenge is the exact single-select poll in section 1. The private store
first durably creates and claims the notification attempt, reserving its
attempt ID, task and generations, exact expiry, destination digest, canonical
dynamic envelope, claim/coordinator fences, descriptor root, and HMAC root.
No send-start fence has yet been crossed.

The capability-authenticated ordinary approval channel then uses two distinct,
closed-schema operations.

#### Prepare

The gateway private host calls `prepare_approval_poll` with the exact fixed
question, ordered options, destination, attempt/task/generations, expiry, and a
fresh private-host nonce. The ordinary bridge:

1. verifies the exact approval-channel capability, transcript, epoch, and
   closed operation schema;
2. verifies destination, account, socket, connection/authority epoch, expiry,
   dynamic-field grammar, exact question bytes, ordered option bytes,
   `selectableCount=1`, and `pollCreationMessageV3`;
3. creates a fresh rc14-compatible custom provider message ID and fresh
   cryptographic 32-byte `messageSecret`;
4. builds the byte-exact `pollCreationMessageV3` with that caller-supplied
   secret, computes raw option identities and the complete payload digest;
5. installs all delivery/vote listeners and a bounded, one-shot ephemeral
   preparation record before any send; and
6. returns authenticated preparation evidence on the same capability-
   authenticated channel.

The evidence contains the preparation ID and generation, attempt/task/request/
challenge generations, provider ID, secret digest but never the secret,
complete payload digest, exact destination, ordinary bundle/account/socket/
connection/authority epoch, expiry, private-host nonce, and option identities.
The held record contains the byte-identical payload, secret, and custom
provider ID. It is unavailable to ordinary chat IPC.

The gateway private host independently reconstructs the expected canonical
payload and evidence under the pinned rc14 compatibility contract, checks every
fixed and dynamic field and digest, and rejects any mismatch. A private-store CAS,
bound to the live claim, coordinator fence, and whole descriptor, writes every
preparation identity/digest into the attempt HMAC and audit state. A separate
durable CAS then crosses send-start and records a fresh send-start generation.
Only after that commit does the gateway private host mint an opaque one-use
signed commit grant. The gateway private host is the only reviewed code path
that opens its Ed25519 signing private key; the ordinary root bundle contains
only the pinned public verification key. Same-UID access to the key file is
within the accepted TCB; the key never appears in environment or argv. The
grant binds every prepared
field, store attempt/version, send-start generation, exact expiry, ordinary
authority epoch, and an exact single-use nonce.

#### Commit-send

The gateway private host passes the signed grant to
`commit_prepared_approval_poll`. The ordinary bridge verifies the signature,
exact channel capability/transcript/epoch, exact preparation match, expiry,
authority epoch, and unused state. It atomically consumes the preparation and
commit
before calling rc14, then invokes `sendMessage()` exactly once with the held
byte-identical payload, held `poll.messageSecret`, and held custom
`messageId`. It constant-time compares the returned ID with the held ID.
Duplicate, expired, foreign, stale, mismatched, or already consumed grants fail
closed. Pinned rc14's `MiscMessageGenerationOptions` custom-ID inheritance and
caller-supplied `poll.messageSecret` behavior are contract-tested.

A process/socket failure after durable send-start is ambiguous even if Node
has not confirmed submission. That attempt/message is never retried. Durable
reconciliation distinguishes exactly: unprepared; prepared but store-unbound;
store-bound prepared but not send-started; send-started with commit outcome
unknown; exact destination accepted; and terminal decision/resolution states.
Unprepared or definitely pre-send prepared state may be superseded only under
the exact bounded policy. Loss of any bridge preparation before send-start
supersedes the attempt and advances challenge generation; the attempt,
provider ID, and secret are never reused. A send-started uncertainty is
consumed ambiguous. Bridge preparation records are bounded, non-persistent,
and never restored.

Approval poll IDs, option identities, option text, secrets, and decrypted
votes never enter the ordinary agent/model message queue. The existing generic
path that aggregates poll selections into ordinary text is not approval
authority and cannot be reused. The bridge maintains a separate authority-only
registry and event channel. It recognizes a tracked approval poll before
ordinary dispatch and suppresses its creation updates and vote updates from
`messageQueue`, whether received through `messages.update`, message upsert, or
another pinned rc14 delivery path.

- A definite failure before the send-start fence may create a new attempt in
  the same generation under bounded store policy.
- After the send-start fence, lack of exact destination-delivery evidence is
  ambiguous. The attempt is consumed; only a new challenge generation may
  proceed where the task has not expired and the state machine allows it.
- Exact destination-delivery evidence makes the tracked poll eligible for a
  decision. It does not itself approve or deny the task.
- Expiry is checked at provider evidence, raw poll decision, atomic decision
  commit, pre-claim, and pre-private-read.

The authority evaluates raw decrypted `selectedOptions` before any text
aggregation. Rc14 identifies an option by SHA-256 of its exact option-name
bytes. Each selected-option byte string is constant-time compared with the two
precommitted identities. Exactly one identity is required. Zero selections,
both options, a duplicate, unknown or malformed bytes, or any text-derived
option fails closed.

A successful AES-GCM decryption is necessary but is not authorization by
itself. The proposed rc14 helper returns both raw decrypted `selectedOptions`
and the exact successful provider-canonical voter-JID candidate; it does not
discard which candidate succeeded. Before option evaluation or durable
mutation, the authority constant-time compares the canonical bytes of that
candidate with the separately provisioned and sealed
`ordinary_approval.expected_owner_voter_jid`. Exactly one successful candidate
must exist and it must equal that expected value. The requester
`owner_sender`, owner-DM destination, local bridge/runtime identity, and
expected remote poll voter are distinct bindings and cannot substitute for
one another. A decryption under any other voter candidate fails closed even
when its authentication tag is valid.

A valid decision binds that equality proof, the exact expected and observed
provider-canonical owner voter JID, private DM destination, ordinary account,
bundle, socket, connection and authority epoch, poll/message keys, poll
creation ID, task, attempt, request and challenge generations, complete
question/payload digest, secret digest, raw option identities,
destination-delivery evidence, authenticated provenance/version, and
observation time. Any second successful candidate, other candidate or JID,
copied or untracked poll, foreign poll, reconnect drift, old generation,
missing pre-send authority state, missing delivery evidence, late event,
duplicate, or post-CAS change fails closed. Rc14 exposes no separately
trustworthy remote device identity, so no remote owner-device field or test is
required.

Vote and destination-delivery events may arrive out of order. Until both exact
conditions exist before expiry, the authority record retains only bounded
non-private authentication/correlation evidence and cannot call the store
decision CAS. The secret is never persisted, and no prior-epoch poll event can
be accepted after authority reattachment.

### Resolution state machine

Approving or denying is one store transaction: it records the owner decision,
decision evidence, immutable audit event, resulting task state, and enqueues
one `approval_resolution` notification attempt. There is no interval in which
the decision exists without its resolution-notification obligation.

The deterministic resolution templates are:

```text
Private-read decision recorded
Request: {task_display_id}
Generation: {challenge_generation}
Decision: approved
Resolution notice expires exactly: {resolution_expiry_rfc3339_utc}
No private mailbox content is included in this notice.
```

```text
Private-read decision recorded
Request: {task_display_id}
Generation: {challenge_generation}
Decision: denied
Resolution notice expires exactly: {resolution_expiry_rfc3339_utc}
No private mailbox content was read or included in this notice.
```

The resolution payload HMAC covers the exact rendered bytes, decision, task,
generation, resolution attempt ID, exact resolution expiry, destination
binding, ordinary adapter/account/socket/epoch, decision-evidence digest,
descriptor digest, and template version. Resolution expiry is deterministically
the decision-recorded instant plus the code-fixed 60-second notification
window. A resolution is exactly one deterministic content-free text message
with no poll, options, button, reaction, or other control. It uses the same
pre-reserved-ID → authenticated prepare evidence → durable store bind →
distinct send-start CAS → one-use signed commit protocol as a challenge,
through closed `prepare_approval_resolution` and
`commit_prepared_approval_resolution` channel operations, without a poll secret
or options.
The ordinary bridge holds the exact rendered bytes and fresh custom provider
ID, installs the one-to-one destination listener before prepare returns,
atomically consumes the matching commit before one rc14 call, constant-time
checks the returned ID, and accepts only the same exact destination
`DELIVERY_ACK`, `READ`, or `PLAYED` evidence.

Definite pre-submit failure may create a fresh resolution attempt before that
expiry. Expiry terminalizes an unstarted or definite pre-submit attempt; an
attempt past its send-start fence remains ambiguous. An ambiguous post-submit
outcome never retries the same attempt/message. The durable decision remains
audit-complete regardless of notification outcome. A late, unknown, or
`SERVER_ACK` signal cannot change the decision or consume authority state.

Pinned Node contract tests exercise the actual reviewed ordinary bridge and
rc14 event adapter, including custom ID inheritance and returned-ID comparison,
caller-supplied poll secret, prepare/bind/send-start/commit ordering,
single-use grant consumption, listener-before-send ordering, exact one-to-one
`messages.update` status mapping, rejection of `SERVER_ACK` and every other
non-accepting signal, group/status failure, raw option SHA-256 identities,
single-selection validation, exact successful owner voter-JID candidate,
authority-only queue suppression, all correlation dimensions, event-order
inversion, restart ambiguity, late events, reconnect, disconnect, timeout,
duplicates, and post-CAS changes. Python mocks alone are insufficient.

### Restart and authority epochs

All three processes are independently supervised; the ordinary bridge is not
assumed to die when the gateway/private host restarts. Every protocol binds
exact process, start, socket, connection, authority, coordinator, signing,
publication, and channel epochs.

A gateway/private-host restart first unpublishes every conversation
capability. It changes coordinator, signing, publication, process/start, and
all channel epochs; reconnects only through a fresh supervisor-created channel
set; authenticates the fresh epoch protocol; commands the ordinary bridge to
purge all prior approval-authority state; and reconciles durable attempts.
Existing session generations never gain a replacement publication. A genuinely
fresh conversation generation is required.

An ordinary bridge restart changes its exact process/start/socket/connection/
authority/channel epochs and destroys every preparation/listener. On fresh
authenticated-channel attachment it atomically purges old preparations,
authority events, and bounded queues before admitting a command. The private
host rejects every prior-epoch event and reconciles each attempt using the
definite-versus-ambiguous send-fence states above.

A sensitive bridge restart changes its exact process/start/socket/connection/
transport/channel epoch and invalidates pending delivery registration under the
existing pre-submit versus post-submit ambiguity rules. Approval events never
use generic ordinary `messageQueue`; their bounded queues are keyed to and
purged by the exact private-host/ordinary-bridge lease epoch. No attempt,
provider ID, secret, or signed commit is retried after an epoch change.

## 6. Gmail OAuth, HTTP, and MIME adapter

### Dedicated exact-scope OAuth grant

V1 uses a new dedicated Google Desktop/native OAuth client. It follows
Google's [OAuth 2.0 for native apps](https://developers.google.com/identity/protocols/oauth2/native-app)
and requests no incremental authorization and no scope except:

```text
https://www.googleapis.com/auth/gmail.readonly
```

Every initial authorization-code token response and every refresh response
must contain a `scope` field. The parser splits only by the specified ASCII
scope separator, rejects empty members, and forms a duplicate-free,
case-sensitive normalized set. Missing `scope`, duplicate scope, extra scope,
differently cased scope, or any set other than the one exact URI fails closed.
The token file binds the dedicated Desktop client identity, refresh-token
grant, exact initial grant set, provisioning version, and expected Gmail
account. `users.getProfile` proves account identity, not scope.

The [Gmail API scope catalog](https://developers.google.com/workspace/gmail/api/auth/scopes)
classifies `gmail.readonly` as a restricted scope. Before OAuth provisioning,
deployment review must determine and satisfy the then-current personal-use,
OAuth verification, and security-assessment policy. This ADR claims no
exemption.

Credentials are new owner-only, one-link, non-symlinked regular files with
closed duplicate-free JSON and bounded size. No broad personal Workspace token,
ambient profile, ADC, keychain default, browser state, CLI cache, environment
credential, or provider URL is used. Normal operation never writes a refreshed
token back to disk.

Initial preparation and every private operation obtain a fresh-enough access
token, validate the exact returned scope, call `users.getProfile('me')`, and
constant-time compare the exact strictly decoded `emailAddress` with the
sealed expected account. Client, grant, scope, or account drift revokes health.

### Fixed requests and partial-response selectors

All requests use `prettyPrint=false`. Authorities and paths are code-fixed.
The three Gmail selectors are:

```text
profile fields=emailAddress
list fields=messages(id,threadId)
get fields=id,threadId,payload(mimeType,filename,headers(name,value),body(attachmentId,size,data),parts(mimeType,filename,headers(name,value),body(attachmentId,size,data),parts(mimeType,filename,headers(name,value),body(attachmentId,size,data),parts(mimeType,filename,headers(name,value),body(attachmentId,size,data),parts(mimeType,filename,headers(name,value),body(attachmentId,size,data),parts(mimeType,filename,headers(name,value),body(attachmentId,size,data),parts(mimeType,filename,headers(name,value),body(attachmentId,size,data),parts(mimeType,filename,headers(name,value),body(attachmentId,size,data),parts(mimeType,filename,headers(name,value),body(attachmentId,size,data),parts(mimeType))))))))))
```

The get selector treats the root payload as depth 0, admits full fields through
depth 8, and includes only `parts(mimeType)` at depth 9 as an overflow sentinel.
Presence of that sentinel fails the depth bound. At every traversable level it
includes only MIME type, filename,
header name/value, and body attachment ID/size/data needed to classify and
parse. Top-level `labelIds`, `snippet`, `historyId`, `internalDate`, and
`sizeEstimate` are excluded. Profile totals and list `resultSizeEstimate`/
`nextPageToken` are excluded.

A Gmail partial-response selector cannot filter `parts[]` by media type. The
bounded response can therefore incidentally contain HTML/attachment metadata
or encoded inline body data. The parser classifies parts before decoding and
never decodes ineligible `body.data` or fetches `attachmentId`.

The exact sequence is:

1. refresh/exchange as required, with exact scope response validation;
2. `GET /gmail/v1/users/me/profile` with `fields=emailAddress` and
   `prettyPrint=false`;
3. `GET /gmail/v1/users/me/messages` with exact `q=in:inbox`, `maxResults=1`,
   `includeSpamTrash=false`, `fields=messages(id,threadId)`, and
   `prettyPrint=false`; and
4. for one result only, `GET /gmail/v1/users/me/messages/{id}` with
   `format=full`, the exact fixed get selector above, and `prettyPrint=false`.

There is no `pageToken`, label parameter, second list/get, attachment request,
or provider URL from configuration. Zero messages returns the content-free no
match outcome. More than one message, missing/duplicate keys, list/get ID or
thread mismatch, oversize/malformed data, or an unsafe MIME tree fails closed.

### Closed parser and DTO

The streamed response cap is enforced first. A duplicate-rejecting JSON loader
then allocates at most the bounded response and validates closed object/type/
depth/entry rules. The iterative MIME walker counts every received part and
header, treats non-empty filename or attachment disposition as attachment,
does not traverse `message/rfc822`, and classifies media type and attachment
state before considering body data.

Only one non-attachment `text/plain` inline leaf with no `attachmentId` may be
eligible. Its base64url text must be canonical and within encoded bounds before
strict bounded decoding. The decoded bytes must be strict UTF-8 or the exact
allowed ASCII-compatible declaration, contain no forbidden controls, and fit
after CRLF-to-LF normalization. Multiple candidates, missing candidate,
attachment-backed plain text, malformed headers, or ambiguous charset fails.

Only root Gmail message payload headers can populate the five header fields.
Every child-part header is retained only long enough for bounded MIME
classification and can never populate or override a DTO output field. Missing
root headers produce `(not present)` regardless of conflicting child headers.
Tests cover each conflicting child header, all missing-root combinations, and
child-only values. Only the six canonical fields enter the slots/redacted DTO.
The renderer uses fixed ASCII field labels, field order, LF separators, no
Markdown, HTML, linkification, locale, model, or adaptive behavior, and asserts
the final 4,096-byte cap.

## 7. Exact task-bound OpenFGA contract

The authenticated deployment uses exactly OpenFGA 1.18.2 from a root-owned
content-addressed runtime bundle. It may run under the existing gateway UID or
a separately existing deployment identity; UID isolation is not a Gmail v1
security claim. It binds only the code-fixed loopback endpoint and requires one
exact high-entropy runtime API credential stored in an owner-only file, never
environment or argv. The gateway UID, OpenFGA process, runtime credential, and
adapter are inside the explicitly accepted TCB.

The gateway private host uses a code-owned closed, bounded adapter exposing only
`Check`, exact model/store metadata read, exact authorization-model bytes read,
and exact standing `approved_reader` tuple reads. All tuple/model/store write
or mutation operations are absent and rejected. The OpenFGA datastore runtime
role is technically read-only for model and tuple data while publication is
possible, so API write attempts fail at datastore authorization even if the
runtime endpoint and credential are reached.

Provisioning has a separately held root/offline writer datastore credential
unavailable in the running Juno environment. It occurs only while Juno private
publication and the OpenFGA runtime are stopped. A root/offline provisioning
authority owns an Ed25519 private signing key unavailable at runtime. Every
policy transaction atomically updates the exact authorization model and the
complete canonical standing `approved_reader` tuple set, increments a
monotonic policy epoch, and emits a signed canonical policy manifest. That
manifest binds store ID, model ID, exact model bytes/hash, exact sorted standing
tuple-set hash/count, policy version/digest, epoch, provisioner key ID, and
deployment generation. Runtime bundles contain only the pinned verification
public key. Provisioning ends with a monotonic epoch advance and the signed
canonical manifest before the read-only runtime is restarted.

The generic model has these semantics for each field object:

```text
durable shared tuple:
  user:<opaque> approved_reader resource_field:<opaque>

contextual task tuples for one check:
  user:<opaque> participant task_grant:<opaque> [task_condition]
  task_grant:<opaque> task resource_field:<opaque>

can_read = approved_reader AND participant from task
```

The conditioned participant tuple binds current time and exact expiry plus
domain-separated digests for request, authorization binding, requester scope,
worker identity, task ID/generation, claim/coordinator generation, OpenFGA
model, policy version, owner-policy epoch, descriptor, field, and check stage.
No Gmail account, query, message ID, header, body, or other private value is in
the model request.

The durable `approved_reader` tuple is separately owned standing owner policy.
Task approval, contextual tuples, reconciliation, expiry, cleanup, or rollback
may not create, restore, modify, or delete it. A contextual
`approved_reader` self-grant is forbidden.

At startup and immediately before each `pre_claim` and `pre_private_read`
six-check group, the private host reads the exact
model bytes/identity and a complete, strictly bounded standing tuple set. It
rejects pagination, duplicates, extras, unknown relations/users/objects,
incomplete reads, count drift, noncanonical ordering, and any set beyond the
small code-fixed maximum. It independently recomputes canonical hashes,
verifies the offline signature and monotonic epoch, and requires byte-for-byte
equality with the signed policy manifest before any `Check`. The read-only
runtime/datastore generation attestation must also prove that no writer can
coexist while the capability is published. Startup configuration alone is
never policy proof.

For each stage, the adapter issues exactly N=6 independent checks, one for each
field in canonical order. It issues N=6 at `pre_claim` and N=6 again at
`pre_private_read`, for 12 requests per successful operation. Every request
contains the exact store/model, relation `can_read`, one field object, the two
and only two contextual tuples above, the exact condition context, and
`HIGHER_CONSISTENCY`. There is no batch, wildcard, composite field, recipients
shortcut, cached allow, or field relation shortcut.

Any false is deny; malformed/error/timeout/redirect/cancellation is failure;
only six exact allows pass a group. Because six checks are not a snapshot, the
store atomically revalidates task state/version, claim and coordinator fences,
request/binding/requester roots, worker and generation, model/policy/owner
epoch, whole descriptor, stage, and expiry after each complete six-check group.
Drift consumes or denies according to the existing side-effect fence.

`HIGHER_CONSISTENCY` is an OpenFGA preference, not a linearizability claim.
The actual standing-policy boundary comes from the datastore-enforced read-only
runtime role, exact
live model/tuple attestation against the signed manifest before both stages,
the absence of runtime mutation authority, and post-group store revalidation.

If exact OpenFGA 1.18.2 plus the selected datastore cannot demonstrably operate
with this read-only runtime role, deployment is blocked. It may not silently
downgrade to application-only no-write discipline.

Tests mutate every contextual binding independently and require deny/failure,
prove the exact two tuples and condition on every call, prove no contextual
standing grant, prove no field/batch shortcut exists, and exercise the full
adapter protocol, tuple/model bounds, manifest signature/epoch, writer exclusion,
pagination/extra/incomplete failures, and both pre-stage attestations. During
engineering the test harness uses only a fake authenticated read-only
datastore/proxy and signed synthetic manifests. OpenFGA installation,
provisioning, and policy epoch advancement are separate deployment approvals.

## 8. Root-owned executable and clean-launch contract on macOS

Live macOS 26.5.2 Python exposes neither `os.fexecve` nor `os.execveat`.
MacOS v1 therefore uses root-owned immutable content-addressed bundles plus
double verification, never path recheck alone or user-writable staging.

The dedicated Juno gateway Python process, ordinary Node bridge, and sensitive
Node bridge each have a different root-owned bundle under a code-fixed root
such as:

```text
/Library/Application Support/Hermes/private-read-bundles/<service>/sha256-<digest>/
```

Each bundle has its own closed, separately hashed manifest and complete
dependency closure. The gateway bundle contains a pinned absolute CPython
interpreter and venv/package closure. Each Node bundle contains a pinned
absolute Node executable and its own package/lock/`node_modules` closure.
Ordinary and sensitive Node graphs are installed and verified independently
and may never import, resolve, or traverse one another. Both independently pin
exactly `@whiskeysockets/baileys@7.0.0-rc14`.

All ancestors and bundle entries are root-owned, non-symlinked, not group/world
writable, and immutable to the gateway UID. Every entry has the reviewed type,
mode, link count, mount identity, and content hash; regular
files are one-link; unknown or missing entries and path/mount substitution fail
closed. Decision records may name only an allowlisted manifest identity
relative to the code-fixed bundle root, never an arbitrary path, command,
executable, module, or import.

For each of the three launchers, the root manifest determines the absolute
verified executable and complete argv, fixed root-owned bundle cwd, the
existing gateway UID/GID, and exact descriptor list. The launcher constructs
an allowlisted environment from empty. It admits only code-fixed locale,
timezone, HOME/state, profile-generation, and inherited-channel values. It
explicitly rejects/removes `NODE_OPTIONS`, `NODE_PATH`,
`PYTHONPATH`, `PYTHONHOME`, every `DYLD_*` and `LD_*` variable, npm lifecycle/
hook/config injection, inspector/debug/preload/require switches, proxy
variables, ambient credential variables, and every unreviewed value.

No launcher inherits a shell, `PATH` resolution, caller cwd, `.env`, default
keychain lookup, `.netrc`, plugin path, user-writable module path, or ambient
configuration. Stdin is `/dev/null`; stdout/stderr go to a dedicated
content-free sink. Every descriptor is close-on-exec and closed before exec
except the exact manifest-allowlisted socketpair endpoints and already-open
validated configuration descriptors. Native loaders and package resolvers
cannot search user-writable locations. The supervisor creates connected
socketpairs before dropping/execing, passes only the allowlisted endpoint FD to
each process, and closes all other copies.

The supervising verifier performs identity, ancestry, ownership, mode, link,
mount, manifest, executable, argv, and full closure validation immediately
before spawn. The in-bundle launcher repeats the same validation before any
dynamic import. Root-owned immutability prevents the gateway UID from
replacing verified bytes between verification and execution within the stated
threat model. Copying into a service- or gateway-writable staging directory is
forbidden.

Deployment evidence binds each launchd record and bootstrap domain to the
exact label, gateway UID/GID, bundle/manifest digest, executable/argv/cwd,
environment digest, descriptor policy, inherited socketpair endpoints, sandbox
profile, memory/CPU/process/file/network limits, log sink, supervision policy,
and rollback identity. Root and kernel compromise remain outside v1.

No bundle, UID, socketpair launch context, launch record, ownership rule, ACL,
or process is installed or mutated during engineering, normal gateway startup,
or this ADR revision. Installation and removal need separate root-authorized
deployment review and rollback proof. Unit tests use an explicit test-only
expected-owner seam; deployment acceptance additionally needs real root-owned
bundle and clean-launch probes.

Native Windows startup fails before credential, session, store, or service
access with an accurate “root-owned macOS runtime bundles required; native
Windows unsupported” status unless another ADR supplies an equivalent
ACL-aware boundary. Pairing is never part of service startup and uses
alphanumeric code only. Sensitive post-submit ambiguity consumes the
authorization; no result retry occurs.

## 9. Dedicated initialization, publication, and cleanup

### Real initialization seam

All constructors remain inert: they perform no network, SQLite, session,
subprocess, socket, path creation, OAuth, Gmail, or OpenFGA work. The root-owned
supervisor starts each process from its anchored manifest and pre-creates the
exact socketpair/channel set. For the dedicated gateway it verifies the exact
bundle and clean-launch context, descriptor-opens the code-fixed decision
record and required owner-only credential/store files, verifies their seals,
and passes only manifest-allowlisted descriptors across exec.

Dedicated gateway/private-host initialization then runs in this exact order:

1. Parse the raw UTF-8 decision-record bytes with the closed duplicate-
   rejecting JSON parser. Verify version, canonical encoding, manifest/seal,
   existing gateway UID, process/start/channel identities, distinct state
   roots, requester descriptor, and all code-fixed file identities without
   creating or mutating them.
2. Before model/provider/client initialization or credential/store access,
   compute and attest the exact `JunoCapabilityManifest`, exact `juno` profile
   and HERMES_HOME generation, then revalidate the gateway, ordinary, and
   sensitive root-bundle/process manifests, clean launch contexts, and
   inherited endpoint descriptors; confirm that the ordinary session remains
   the complete canonical directory.
3. Through the code-owned read-only adapter, verify exact OpenFGA runtime,
   store/model bytes, signed policy manifest, complete standing tuple set,
   policy epoch, and read-only/no-writer generation.
4. Perform the initial OAuth exchange or refresh, exact scope validation, and
   Gmail profile/account verification without reading a message; then verify
   ordinary account/authority readiness and offline sensitive account/session
   readiness without sending.
5. Open the private authorization store; acquire the fork-safe singleton OS
   lock; then atomically reconstruct/acquire the coordinator fence and run
   descriptor reconciliation in the same database transaction. Publish the
   coordinator fence only after commit, then create the worker and fresh
   ordinary/sensitive authenticated leases. Reconciliation never precedes the
   singleton lock and fence-acquisition transaction.
6. Recheck every seal, descriptor, policy attestation, channel epoch,
   requester binding, process generation, Juno capability manifest, and health
   predicate. Only then permit the in-process publication transaction below.

Partial failure closes every acquired slot in strict reverse order. No failed
step can leave a store, lock, coordinator, worker, approval lease, sensitive
registration, client, or publication live. The private provider, store,
worker, credentials, and plaintext remain inside reviewed private frames in the
dedicated gateway process and never enter model-facing frames or results.

Synchronous `compose_trusted_private_read_services()` performs inert code-owned
construction of the built-in Gmail, OpenFGA, authorization-store, ordinary-
approval, and sensitive-delivery adapters. At the existing async
`GatewayRunner._start_trusted_private_read_host()` seam in
[`gateway/run.py`](../../gateway/run.py), it binds the exact closed decision
record, root bundle, runtime objects, inherited channel endpoints, requester,
Juno capability manifest, protocol, schema, and publication generation. It
returns a concrete built-in in-process composition, never `None`, only after
exact attestation; it cannot accept a callback, factory, import, URL, command,
arbitrary socket, environment-selected provider, or arbitrary provider/store
implementation. Pre-publication failure closes the composition directly.

### Atomic publication

A reviewed publication-registry module owns one process-global synchronous
`threading.RLock` and one authoritative immutable
`PrivateReadPublicationSnapshot`. The snapshot contains at least:

- publication state (`empty`, `published`, or permanently `failed`),
  private-host authority and health identity;
- event authority, process/bundle identity, and monotonic publication
  generation;
- the in-process terminal handler and immutable public operation registry;
- exact schema generation, canonical tool schema bytes, and tool metadata;
- requester/profile generation and authenticated provenance;
- exact `JunoCapabilityManifest` digest, allowlist, registry-source, plugin,
  hook, MCP, model, profile, instruction, and HERMES_HOME identities; and
- the empty/failed reason code without private data.

After all preparation, async startup performs one short non-awaiting snapshot
swap under that lock. No network, filesystem access,
health check, logging callback, cleanup, event dispatch, tool-registry
mutation, or `await` occurs while it is held. Rollback and shutdown first swap
to an empty or failed snapshot at a higher generation under the same lock and
only then perform awaited cleanup. No partial client/event/tool interval exists.

Every synchronous authority reader obtains one immutable snapshot through the
same registry and lock: authenticated event binding, busy-principal checks,
new-session capability/schema capture, service-gated discovery, terminal-handler
dispatch, shutdown, and runner diagnostics. A publication swap advances the
availability generation before any new conversation can be constructed.
`GatewayRunner._trusted_private_read_host` and any other runner fields are
non-authoritative diagnostics only; if retained, they are set during the same
short commit and authority code never reads them directly.

The private-read tool may remain statically registered in `tools/registry.py`.
Its availability bypasses generic TTL and last-good caches. Every genuinely
new session capture reads exactly one publication snapshot. The tool registry
is not mutated on publication. `model_tools.py` includes publication identity,
generation/state, requester identity, and schema digest in the definition
cache key together with the `JunoCapabilityManifest` digest and exact
allowlist/plugin/model/profile identity, so stale present or absent results
cannot cross an availability generation.

`agent/agent_init.py` atomically captures the immutable
`PrivateReadConversationCapability` with definitions, schema bytes, registry
generation, the full Juno manifest identity, and the new gateway session/
conversation generation. The gateway persists that content-free capability in
session-generation metadata before
model construction. Rebuilding an evicted agent or restarting the gateway for
an existing session reloads it; it cannot recapture current availability.

`agent/tool_executor.py` direct terminal planning/execution and deferred Tool
Search definition/scope planning accept only that session-bound capability.
They compare it with the one current publication solely for exact equality or
revocation and never acquire a newer terminal handler. Existing conversation
tool and prompt bytes remain unchanged even when execution is revoked.

Lock order is fixed: `tools/registry.py` takes its own registry snapshot first,
releases that lock, and then performs a short publication-snapshot read. A
publication swap never acquires the tool-registry lock. This prevents lock
inversion while keeping schema discovery and terminal dispatch coherent.

Mandatory seam migration covers the `model_tools.py` definition cache;
`agent/agent_init.py` schema/registry capture; `agent/tool_executor.py` direct
planning and execution; deferred Tool Search definition and scope planning;
gateway new-session generation creation and persisted metadata; agent
eviction/rebuild for an existing session; the busy-principal check near
`gateway/run.py:6680`; authenticated event binding near
`gateway/run.py:24053`; shutdown/unpublication near `gateway/run.py:12828`;
and every runner diagnostic. No separate live pointer is authority at any seam.

### Non-discardable cleanup

Cleanup is bounded, shielded, reverse-order, and owned within each process.
Gateway cleanup first synchronously unpublishes at a higher generation, then
closes its in-process private-host composition and content-free capability
bindings. Private-host cleanup records slots as acquired and attempts all of
them even after an earlier failure: worker, coordinator, store, sensitive
registration/channel, ordinary authority lease/channel, OpenFGA adapter,
Gmail/OAuth streams/clients, token/DTO/body references, decision-record/bundle
descriptors,
and controlled buffers. Each bridge independently purges epoch-scoped
registrations/listeners/queues and closes its sockets without exposing session
state. Cleanup errors are aggregated only as content-free codes.

Cancellation cannot discard cleanup. Each supervisor/process starts one owned
cleanup task, shields and awaits it within a fixed bound, and proves each
absence or closure visible to that identity. Failure or timeout leaves gateway
publication empty or failed at a higher generation and service health
permanently failed. The original private exception graph is not retained when
cancellation/control flow is recreated.

### Exact proposed file changes

- `gateway/private_read_host/` code-owned modules: own generic proposal/grant
  consumption, content-free outcomes, worker/coordinator ordering, exception
  frames, and the concrete in-process composition. They are not a service
  server and expose no arbitrary injection surface.
- `gateway/private_read_host/config.py` and `seals.py`: parse the raw canonical
  duplicate-rejecting decision record and verify its exact owner file, bundle,
  and manifest identities before object construction.
- `gateway/private_read_host/gmail_provider.py`, `oauth.py`, `mime.py`, and
  `renderer.py`: implement generic Gmail HTTP/OAuth/MIME/privacy behavior,
  deterministic output, and the private fake-transport test seam.
- `gateway/private_read_host/authorization_store.py` and `coordinator.py`:
  extend the generic store protocol for prepare, durable bind, send-start,
  signed commit, reconciliation, restart recovery, claim fences, and HMACs.
- `gateway/private_read_host/openfga_runtime.py` and `policy_manifest.py`:
  implement the authenticated read-only adapter, exact live model/standing-
  tuple reads, 12 checks, and signed canonical policy verification.
- `scripts/whatsapp-bridge/approval_authority.mjs` plus its bridge wiring: add
  the dedicated capability-authenticated approval channel, prepare/commit/
  event lease, exact successful voter-JID return, one-shot records, queue
  suppression, and
  epoch purge. Ordinary gateway chat IPC stays separate.
- `gateway/private_read_host/ordinary_approval.py`: implement exact channel-
  capability verification, preparation evidence, signed commit, and epoch-
  scoped event handling for the ordinary authority.
- `scripts/whatsapp-sensitive-bridge/delivery_authority.mjs` plus its bridge
  wiring: add the capability-authenticated inherited private-plaintext channel
  and fixed terminal evidence response without plaintext return.
- `gateway/private_read_host/sensitive_delivery.py`: own the fixed plaintext-
  send request, channel/epoch checks, and content-free terminal evidence.
- `gateway/private_read_publication.py`: own the process-global synchronous
  `threading.RLock`, immutable `PrivateReadPublicationSnapshot`, monotonic
  availability generation, swap/unpublish, and sole authority read API.
- `gateway/private_read_conversation_capability.py`: define and persist the
  immutable content-free session-generation capability and exact-current
  equality/revocation rule, including Juno manifest identity.
- `gateway/juno_capability_manifest.py`: canonicalize and attest the exact
  profile, model, tool definitions/handlers/registries, plugin/hook/MCP lists,
  HERMES_HOME generation, and strict absence allowlist at every required seam.
- [`gateway/trusted_private_read_host.py`](../../gateway/trusted_private_read_host.py):
  make `compose_trusted_private_read_services()` the concrete built-in in-
  process composition; remove `None` and arbitrary factories.
- [`gateway/run.py`](../../gateway/run.py): publish/unpublish only through the
  synchronous registry; migrate new-session persistence, rebuild, busy-
  principal, event-binding, shutdown, and diagnostics to one snapshot.
- [`tools/private_read_request_tool.py`](../../tools/private_read_request_tool.py):
  keep one static service-gated, content-free registration and execute only the
  session-bound in-process terminal capability.
- [`tools/registry.py`](../../tools/registry.py),
  [`model_tools.py`](../../model_tools.py), `agent/agent_init.py`, and
  `agent/tool_executor.py`: add publication/Juno-manifest identity, state, and
  schema digest to definition caching and carry the session-bound capability
  through direct and deferred Tool Search planning without runtime
  re-resolution.
- `services/launch/` and three closed root-bundle manifests: implement the root
  supervisor/socketpair capability bootstrap and verify exact executable/argv/
  cwd/environment/descriptors/gateway-UID/hash closures for the dedicated Juno
  gateway, ordinary bridge, and sensitive bridge.
- `scripts/release/verify_juno_private_read.py`,
  `scripts/release/juno-private-read-release-v1.json`, and
  `scripts/release/validate_node_runtime_docs.py`: implement the closed release
  matrix, artifact/evidence manifests, status-aware type gate, Node installs/
  tests/audits, docs validation, and full-suite orchestration.
- Focused Python and Node contract tests cover every protocol, privacy,
  policy, launch, publication/session, restart, release-manifest, and lifecycle
  boundary above; documentation records the default-off engineering state and
  separately authorized deployment procedure.

## 10. Relay release boundary

Gmail/Juno native local WhatsApp is independent of the relay. Relay capability
negotiation and an unidentified connector deployment are not Gmail v1 release
prerequisites.

This release preserves the already accepted WebSocket deadlock and principal/
session cleanup fixes where they are independently safe. It removes or ignores
unverified relay `authenticatedUserId` as authority. Discord relay prompt
component/control resolution is disabled unconditionally and fails closed
because this repository proves neither a connector producer nor capability
negotiation. Ordinary relay message behavior remains unaffected where it does
not resolve a prompt component or mutate private-read state.

Focused tests prove Discord components cannot pop, approve, deny, resolve, or
otherwise mutate pending state; spoofed, missing, or present
`authenticatedUserId` makes no difference; late/reconnected component events
remain inert; ordinary relay messages still follow their safe existing path;
and local Juno WhatsApp approval works with the relay absent.

Discord relay components are deferred to a separate ADR and coordinated
connector rollout with a proved producer/version/protocol. No such work may be
smuggled into the Gmail activation gate.

## 11. Dedicated closed decision record

There is exactly one deployment source for this feature: the versioned JSON
decision record named `config-v1.json` at a launcher-compiled absolute path in
the canonical owner-only Juno private-read state directory. Main
`config.yaml`, profile overlays, managed configuration, environment, CLI,
plugins, and legacy `gateway.trusted_private_read` cannot redirect, populate,
or override it.

The file must be a bounded regular one-link non-symlink, owned by the gateway
UID, mode `0600`, with root-owned ancestry and bundle-manifest binding where
practical. Its device/inode, owner, mode, link count, byte length, SHA-256, and
relative sealed file identities are bound by the gateway root manifest and
deployment seal. The root launcher descriptor-opens and validates it before
exec; the gateway private host revalidates the passed descriptor and bytes
before parsing.

Raw bytes are strict UTF-8 JSON. Parsing rejects a BOM, invalid UTF-8,
duplicate keys at any depth, unknown/missing/wrongly typed keys, booleans used
as integers, floats where integers are required, integers outside their closed
ranges, invalid enum/string grammar, non-NFC or alternate Unicode
normalization, noncanonical escapes/numbers/key ordering/whitespace, trailing
data, and any byte sequence different from the code-owned canonical encoder's
output. Duplicate detection happens in the token parser before object
construction. There is no interpolation, YAML tag/anchor/alias/merge, env
expansion, overlay, profile inheritance, or legacy precedence.

The closed version-1 object contains only these groups:

- `version` exactly `1` and required boolean `enabled`; engineering artifacts
  contain `false`, and only a separately approved deployment transaction may
  replace and reseal this same canonical record with `true`;
- exact `process_identities` for the dedicated Juno gateway, ordinary bridge,
  sensitive bridge, and OpenFGA runtime, including expected UID/GID values,
  bundle/process/start/channel identities, and the required channel matrix;
- exact `service_bundles` manifest version/digest/deployment generation for
  gateway, ordinary, sensitive, and OpenFGA runtime;
- the closed eight-field `requester` descriptor from section 4;
- exact `state_files` root-relative sealed identities for the private store,
  HMAC key, commit-signing key, policy manifest, Gmail OAuth client/token, and
  sensitive session directory, plus only a seal/digest identity for the
  code-fixed complete ordinary session directory at its canonical path; the
  record contains no absolute or parent-relative arbitrary path;
- `capability` fixed to operation version 1, capability ID
  `gmail.newest_inbox_message.read`, exact query `in:inbox`, exact ordered six
  fields, label, poll template/version/options, and descriptor digest;
- `gmail` fixed to kind `gmail_v1`, the one exact scope, sealed expected-account
  binding, client/grant identity, and Gmail provider contract digest;
- `openfga` fixed to version 1.18.2 with exact store/model identities, model
  hash, signed policy-manifest identity/digest, policy version/digest,
  monotonic epoch, sorted standing-tuple hash/count, provisioner public-key ID,
  read-only runtime generation, and authenticated adapter identity;
- `ordinary_approval` with exact ordinary account/session/bundle/channel/
  authority identities, owner DM destination binding, and one separately
  provisioned canonical `expected_owner_voter_jid`; this value is required for
  the constant-time post-decryption equality check and is distinct from both
  requester `owner_sender` and the destination binding;
- `sensitive_delivery` with exact sensitive account/session/bundle/channel/
  transport identity and destination/thread binding; and
- `limits`, containing only integer milliseconds/byte/count values that can
  reduce, never enlarge, the code maxima in section 3. Decimal floating-point
  seconds are not accepted.

The record cannot contain commands, executable names, import/module/callable
names, URLs, provider factories, arbitrary socket or filesystem paths, Node or
Python paths, alternate authorities, arbitrary queries/fields/copy, or any
extension object. File identities are only code-fixed-root-relative sealed
names from a closed enum. Code fixes Gmail/OAuth authorities and selectors,
OpenFGA loopback authority, relations, templates, bundle roots, executables,
and closed in-process/channel schemas.

Presence of any legacy private-read YAML/config key or environment variable is
an activation failure with one fixed content-free migration code; it is never
merged. Only the reviewed gateway private host opens the record. Model-facing
frames receive only the content-free publication and never account,
destination, policy, credential, session, or key identities.

A malicious same-UID process can technically read or alter owner files and is
inside the accepted TCB. HMACs and seals are drift/corruption detection within
that TCB, not same-UID adversary isolation.

## 12. Verification and implementation plan

No gate below is claimed passing. Implementation begins only after this ADR is
accepted and proceeds in small reviewed slices.

### Product and generic authorization contracts

Tests first fix the exact capability/query/label/fields, requester binding,
descriptor/HMAC domains, cache-stable schema discovery, generation replacement,
conversation-capability persistence, eviction/restart behavior, direct and
deferred execution, whole-descriptor reconciliation matrix, and two unrelated
synthetic provider adapters. They prove no Gmail branch enters generic
authorization and no query/account plaintext enters model, schema, store,
policy, audit, gateway IPC, or ordinary notifications.

Dedicated-Juno tests prove the exact profile/HERMES_HOME generation and
canonical `JunoCapabilityManifest` before client initialization and at every
attestation seam. They exhaustively reject every forbidden terminal, file,
code, browser, computer-use, messaging, memory, cron, delegation, skill,
plugin, hook, MCP, discovery, profile-crossover, and arbitrary-backend route;
extra/missing/replaced tools or handlers; schema/registry drift; and model or
profile drift. They test the exact optional `web_search` predicate and the
only-private-tool fallback.

### Gmail and OAuth boundary

Tests cover both initial and refresh responses with exact scope, all missing/
duplicate/extra/case variants, dedicated client/grant binding, account drift,
fixed methods/authorities/paths/query/selectors/`prettyPrint=false`, redirects,
stream caps, response allocation order, duplicate JSON, MIME budgets,
incidental receipt, no ineligible decode or attachment fetch, DTO repr/str,
root-only header provenance, conflicting child headers, missing root headers,
deterministic rendering, exception graph hygiene, cancellation, and every
content-free outcome.

The real local fake Gmail HTTPS and OpenFGA harness uses a non-configurable
test-only transport injection. Production constructors and config expose no
endpoint override. A test-only capability object, created only by the pytest
harness and passed through a private test constructor, may replace the socket
dial target while the logical request authority, Host/SNI expectations,
methods, paths, and query remain code-fixed and asserted. Production startup
cannot construct or select that capability from config, environment, plugin,
or CLI. Tests run serially where global hooks are unavoidable and otherwise
bind loopback port `0`, record the assigned ephemeral port, and use an
ephemeral CA. Production authorities remain unchanged.

### OpenFGA, approval, sensitive transport, lifecycle, and relay

Tests prove the exact shared/contextual tuple model, condition dimensions,
12 independent higher-consistency checks, atomic post-group revalidation,
standing-policy ownership, signed live model/tuple attestation, read-only writer
exclusion, and all independent mutation failures. Approval tests cover the
exact poll question, ordered raw option bytes/hashes, variant, selectable
count, prepare/bind/send-start/signed-commit, deterministic resolution payload,
atomic decision enqueue, custom rc14 message IDs/secrets, pre-send listeners,
exact destination status mapping, successful canonical voter-JID return,
constant-time equality with the separately sealed expected owner-voter JID,
rejection of a successfully decrypted vote from every non-owner candidate,
rejection of zero or multiple successful candidates, distinct requester/
destination/voter bindings, authority-only queue suppression, out-of-order
evidence, every reconciliation state, epoch purge, retry/ambiguity/expiry, and
pinned Node behavior. Root-
bundle tests cover all three executable/closure/clean-launch contracts,
application separation, inherited socketpair capability bootstrap, test-owner
seams, and real deployment probes. Sensitive tests cover channel
authentication, no-plaintext response, account/session
separation, and exact ACK meanings. Lifecycle tests inject `BaseException`,
cancellation, and process restarts at every construction, initialization,
lease, publication, read, send, unpublish, and cleanup slot. Relay tests prove
Discord components are inert and Juno is independent.

### Reproducible Python type gate

Type reports record both the parent/base and candidate. For the reviewed WIP:

```text
source commit: 49d78bdc915e9e2c3ff78d7d4a3a7074ddb6ac85
source parent: 0595c3816d9d67a3c409f7671520cadd4c2d32a8
tool: ty==0.0.21
```

The observed changed-Python status map from that parent is:

```text
M gateway/platforms/base.py
M gateway/relay/adapter.py
M gateway/relay/ws_transport.py
M gateway/trusted_private_read_host.py
M tests/gateway/relay/test_relay_interactive.py
M tests/gateway/relay/test_relay_passthrough.py
M tests/gateway/relay/test_relay_per_platform_caps.py
A tests/gateway/relay/test_ws_callback_dispatch.py
M tests/gateway/relay/test_ws_transport.py
A tests/gateway/test_active_principal_lifecycle.py
M tests/gateway/test_trusted_private_read_host.py
M tests/test_install_ps1_whatsapp_home_and_node_contract.py
```

Implementation adds a dedicated repository-owned tool environment:

- `tools/type-gate/pyproject.toml` pins exactly `ty==0.0.21` and no floating
  checker dependency;
- `tools/type-gate/uv.lock` locks that environment and records exact artifacts
  and SHA-256 hashes for every reviewed release platform; and
- a repository release script plus reviewed toolchain manifest pins the exact
  `uv` executable path, version, SHA-256, and supported platform identity.

The manifest separately pins a hash-verified CPython 3.13 macOS-arm64 artifact
and absolute interpreter for this release lane. Evidence archives its path,
version, SHA-256, upstream artifact identity, build/configuration identity, and
platform. Other platform lanes require separately reviewed explicit artifacts
and `--python-platform` values.

The script first verifies that exact `uv` and CPython identity. In a
command-scoped owner-only environment with no ambient Python/tool
configuration, it creates the exact ty environment from its own lock with the
equivalent of
`[verified_uv, "sync", "--locked", "--offline", "--python", verified_cpython,
"--project", "tools/type-gate"]`. It also
creates a different owner-only project environment for each parent/candidate
revision, synchronized offline from that revision's root `pyproject.toml` and
root `uv.lock` with every exact dev/test extra required for source imports,
including pytest. The project command is equivalent to:

```text
[verified_uv, "sync", "--locked", "--offline", "--all-extras",
 "--python", verified_cpython, "--project", revision_root]
```

Each environment uses a fresh hash-verified complete artifact mirror and
revision-private cache; no venv, package cache, interpreter environment, or
site-packages is shared between revisions or with the ty environment. After
sync, the orchestrator verifies and archives the complete installed
distribution inventory and artifact digests. It separately verifies the
resulting `ty` path, version `0.0.21`, executable SHA-256, distribution
metadata, and artifact identity. No ambient `ty`, `uvx`, network resolution,
floating index, mutable shared cache, or unspecified lock is accepted.

Release verification creates isolated owner-only source trees for the exact
parent and candidate, plus separate owner-only tool/cache/home/temp state. Its
status-aware algorithm is:

1. Run and archive the byte-exact output of
   `git diff --raw -z --abbrev=40 --find-renames=100% --find-copies=100% <parent> <candidate> -- '*.py'`.
   Parse NUL-delimited records without a shell, retaining status, modes, blob
   IDs, similarity, and old/new paths. Accept only `M`, `A`, `D`, `R100`, and
   `C100`; reject any other, malformed, or unmerged status and any non-UTF-8
   repository path.
2. Build and archive two revision-specific NUL-delimited manifests. `M` and
   other ordinary common paths run in both revisions. `A` paths run only in
   the candidate; `D` paths only in the parent. `R100` and `C100` run the old
   parent path and new candidate path and record an explicit canonical
   old-to-new mapping. Never pass an absent path. In this comparison the two
   `A` tests above are candidate-only and are absent from the parent
   invocation.
3. Abort separately if a revision that should have applicable paths has an
   empty manifest. An intentionally inapplicable revision is recorded as such,
   not passed as an empty checker invocation.
4. Invoke the verified checker directly with this exact argv array from the
   exact revision root, never through a shell:

   ```text
   [verified_ty, "check",
    "--project", revision_root,
    "--python", revision_project_python,
    "--python-version", "3.13",
    "--python-platform", "darwin",
    "--output-format", "gitlab",
    "--no-progress", "--color", "never",
    "--", *revision_paths]
   ```

   Archive cwd, argv, environment digest, exit status, stdout and stderr
   exactly. Exit 0 is accepted only with an empty diagnostic array; exit 1 only
   with a valid non-empty array. Exit 2 or any other status is infrastructure
   failure. Missing/unreadable paths, checker crashes, or non-JSON output fail.
5. Accept ty 0.0.21 GitLab output only as a top-level JSON array of closed
   diagnostic objects. Each object has exactly required string
   `description`, `check_name`, `fingerprint`, and `severity`, plus a closed
   `location` whose required `path` is a string and whose closed
   `positions.begin` and `positions.end` each have positive integer `line` and
   `column`. Booleans are not integers. Unknown/missing fields or types,
   invalid coordinates, invalid UTF-8, and severity outside the pinned observed
   set `{major}` fail as infrastructure/schema errors. The complete
   `description` is the comparison message after only UTF-8/LF and exact-root
   normalization already defined below: no trimming, stripping, truncation,
   or diagnostic-text rewrite. Archive `fingerprint` but never use it to waive
   a mismatched full key.
6. Strictly parse and canonicalize every diagnostic to this full comparison
   key: canonical candidate-relative POSIX path after the explicit rename/copy
   mapping; mapped start line and column; mapped end line and column; exact
   check/rule name; severity; and exact normalized message. Coordinates are
   positive one-based integers after conversion from the pinned output schema.
   Message normalization requires valid UTF-8 and LF, rejects ANSI, replaces
   only the exact checkout root with `<repo>`, and performs no other lossy
   rewrite. Ordering does not affect set membership, but duplicate counts are
   archived.
7. Generate and archive zero-context Git diff hunk maps for every common,
   rename, and copy pair. Apply cumulative line offsets. A parent range maps to
   candidate coordinates only if every line spanned by its start/end range is
   unchanged; its columns then remain exact. Parent diagnostics touching a
   deleted or replaced range have no baseline mapping. Candidate diagnostics
   touching an added or replaced range are candidate-only. A candidate
   diagnostic on an unchanged mapped range is subtracted only by an exact match
   of the complete key above.
8. Treat every added-file diagnostic as candidate-only. Archive deleted-file
   diagnostics as parent-only; they cannot subtract. Compare copies from old
   parent path to new candidate path and renames through their canonical path
   mapping.
9. Archive raw checker totals and exit statuses, revision-specific manifests,
   the status map, zero-context hunk maps, raw and normalized reports, mapped
   and unmatched parent diagnostics, the exact matched baseline multiset, and
   the exact candidate-only multiset.

The previously supplied candidate-only count of 26 is a target to reproduce
and archive before fixes, not a certified count. After fixes, acceptance
requires zero candidate-only diagnostics. No suppression, exclusion, inline
ignore, baseline waiver, missing-path invocation, or empty-manifest invocation
is permitted. Command-scoped `UV_CACHE_DIR`, `XDG_CACHE_HOME`, tool home, and
temp paths are owner-only and destroyed after evidence capture.

### Reproducible Node, package, docs, and test gates

Implementation adds one repository-owned orchestrator and two closed
validators/manifests:

- `scripts/release/verify_juno_private_read.py`;
- `scripts/release/juno-private-read-release-v1.json`; and
- `scripts/release/validate_node_runtime_docs.py`.

The release manifest is versioned, canonical, duplicate-rejecting, and closed.
For every lane it names the exact argv array, cwd, allowlisted environment,
source OIDs, input/artifact hashes, expected output/test manifest, evidence
path, and acceptance predicate. The orchestrator and manifest are themselves
tested: a missing lane/path/artifact/output, nonzero exit, skipped or zero-test
run, network use in an offline lane, environment drift, extra/missing package,
or unarchived required evidence fails the release.

#### Node and npm lanes

The two exact package roots are `scripts/whatsapp-bridge` and
`scripts/whatsapp-sensitive-bridge`. For each, the manifest pins the absolute
root-bundle Node executable path, version, SHA-256 and artifact/build identity,
plus the absolute npm CLI JavaScript entry path, npm version/SHA-256, and its
complete dependency closure. Npm is invoked only as
`[verified_node, verified_npm_cli, ...]`, never through `PATH` or a package
script.

For each exact lock, release preparation creates a content-addressed offline
tarball cache containing every and only the required package artifact. A
separate hash manifest binds package name/version/integrity, tarball SHA-256,
relative cache path, lock/package hashes, and complete cache tree; independent
verification rejects extra, missing, mutable, or mismatched bytes before use.
Each lane copies only reviewed package/lock/source bytes to a fresh owner-only
work root and invokes exactly:

```text
[verified_node, verified_npm_cli, "ci", "--offline", "--ignore-scripts",
 "--cache", verified_package_cache, "--no-audit", "--no-fund"]
```

The orchestrator denies network, verifies package/lock/source/tree hashes
before and after, and archives the installed dependency inventory/digests.
Direct Node test argv is exactly
`[verified_node, "--test", "--test-concurrency=1", *test_files]`; package test
scripts are bypassed.

The ordinary sorted test manifest contains the existing eight files
`allowlist.test.mjs`, `bridge.native.test.mjs`,
`bridge.reconnect.test.mjs`, `bridge.sendqueue.test.mjs`,
`outbound_ids.test.mjs`, `owner_message_gate.test.mjs`,
`preimport_identity.test.mjs`, and `transport_identity.test.mjs`, plus the new
`approval_authority.test.mjs` and `clean_launch.test.mjs`. The sensitive sorted
manifest contains the existing eleven files `delivery_core.test.mjs`,
`entrypoint.test.mjs`, `http_server.test.mjs`, `lifecycle.test.mjs`,
`offline_provision.test.mjs`, `pin_and_identity.test.mjs`,
`preimport_identity.test.mjs`, `provisioning_core.test.mjs`,
`rc9_compatibility.test.mjs`, `real_auth_state.test.mjs`, and
`session_paths.test.mjs`, plus `delivery_authority.test.mjs` and
`clean_launch.test.mjs`. The manifest stores their full relative paths and
hashes and rejects discovery-based additions or omissions.

After all offline gates, each package has a distinct intentionally online,
mutable-current audit lane with exact argv
`[verified_node, verified_npm_cli, "audit", "--json", "--package-lock-only"]`.
Acceptance requires valid closed audit JSON and zero vulnerabilities at every
severity. Evidence archives registry authority, request time, response
identity/body hash, npm/Node identities, package/lock hashes, and exit status;
it is never represented as reproducible offline evidence.

#### Documentation lane

`validate_node_runtime_docs.py` obtains a NUL-safe tracked-file manifest from
the exact candidate OID, classifies every file to its owning package/product,
and extracts every root-Hermes Node runtime claim from canonical and translated
READMEs, documentation, installers, and package manifests. It emits canonical
JSON entries with exact `path`, `line`, `owner`, and `claim`. Every root claim
must mean `>=22.22.0`; unrelated package requirements are preserved;
unclassified or ambiguous claims fail. Evidence archives validator source/
executable hash, source OID/manifest hash, classified input hashes, and output
hash.

#### Python and full-suite lanes

The same verified CPython/artifact mirror creates one exact checkout-local root
`.venv` from the candidate root `uv.lock` and all required extras using the
offline locked `uv sync` contract above. `scripts/run_tests.sh` is invoked only
after that `.venv` exists and its interpreter/distribution inventory/digests
match the manifest; the orchestrator records and verifies the interpreter
selected by the runner.

The release manifest defines these exact focused groups as closed arrays:

- `provider_privacy`: `tests/gateway/private_read_host/test_gmail_provider.py`,
  `tests/gateway/private_read_host/test_gmail_mime_privacy.py`, and
  `tests/gateway/private_read_host/test_oauth_boundary.py`;
- `authorization_store_notifications`:
  `tests/gateway/test_private_read_authorization.py`,
  `tests/gateway/test_authorization_task_store.py`, and
  `tests/gateway/private_read_host/test_notification_protocol.py`;
- `publication_session_tool_search`:
  `tests/gateway/test_trusted_private_read_host.py`,
  `tests/gateway/test_trusted_private_read_event_scoping.py`,
  `tests/gateway/test_active_principal_lifecycle.py`, and
  `tests/tools/test_private_read_conversation_capability.py`;
- `relay`: `tests/gateway/relay/test_relay_interactive.py`,
  `tests/gateway/relay/test_relay_passthrough.py`,
  `tests/gateway/relay/test_relay_per_platform_caps.py`, and
  `tests/gateway/relay/test_ws_callback_dispatch.py`;
- `config_installers`: `tests/gateway/private_read_host/test_config_v1.py`,
  `tests/services/test_root_bundle_launch.py`, and
  `tests/test_install_ps1_whatsapp_home_and_node_contract.py`;
- `ordinary_bridge` and `sensitive_bridge`: the exact Node manifests above;
  and
- `lifecycle`: `tests/gateway/test_lifecycle_ledger.py` and
  `tests/gateway/private_read_host/test_process_lifecycle.py`.

Each Python group runs as a separate exact
`[revision_project_python, "-m", "pytest", "-q", *group_paths]` process;
terminal/private groups remain separate where SQLite process interference is
possible. The orchestrator then runs the canonical full Python suite as exact
argv `["scripts/run_tests.sh", "-j", "4"]` from the repository root, with the
verified checkout-local `.venv`. Ruff runs as
`[revision_project_python, "-m", "ruff", "check", "."]`. The syntax lane builds
a NUL-safe sorted manifest of every tracked Python file and invokes deterministic
batches of `[revision_project_python, "-m", "py_compile", *batch_paths]`.
Thereafter it runs the status-aware ty gate, both direct Node suites, docs
validator, both frozen installs, both online audits, and release-orchestrator
self-tests.

All `HOME`, `HERMES_HOME`, `TMPDIR`, bytecode, npm, uv, XDG, and tool-cache
roots are command-scoped owner-only directories and are destroyed after
evidence is sealed. Engineering uses synthetic identities and fake local
services only. Privacy sentinels are scanned across logs, exception graphs and
locals, tasks/coroutines, HTTP objects, SQLite/WAL/journal, audit/policy bodies,
files, model/session/memory, argv/environment, caches, and result objects.

## 13. Deployment activation boundaries

These approvals are separate, ordered, and non-transitive. Approval of one
does not imply any later action:

1. Accept this ADR and land the separately reviewed implementation, including
   the exact query, output, poll, risk acceptance, and default-off behavior.
2. Install and approve the root-owned gateway, ordinary, and sensitive bundles
   plus the clean supervisor/socketpair launch context, manifest closure,
   resource limits, rollback, and removal. All run as the existing gateway UID;
   no service UID is created and the ordinary session is only verified in
   place, never copied or ownership-transferred.
3. Approve and attest the exact Juno profile/HERMES_HOME generation and
   `JunoCapabilityManifest`, including source/bundle, model, tool, handler,
   registry, plugin, hook, MCP, schema, and profile-instruction identities.
4. Generate, review, install, and seal the owner-only default-off private
   decision record, HMAC/commit-signing keys, and authorization store without
   publishing the feature.
5. Provision the offline-signed OpenFGA model and complete standing tuples with
   the separate root/offline writer while Juno publication and the runtime are
   stopped; advance and seal the epoch; remove writer availability; then start
   and attest exact OpenFGA 1.18.2 with the datastore-enforced read-only runtime
   role and owner-file runtime credential.
6. Create the dedicated Gmail Desktop OAuth client/token, satisfy the then-
   current restricted-scope policy, and prove the exact `gmail.readonly` grant.
7. Provision and pair sensitive WhatsApp by alphanumeric phone-link code only;
   QR is absent.
8. Separately start and attest the ordinary bridge and sensitive bridge,
   proving their exact bundles, separate accounts/sessions/dependency graphs,
   process/start/socket/connection/channel/authority epochs, ordinary chat-
   versus-approval separation, and sensitive delivery separation.
9. Install the candidate default-off. Separately approve enable/restart, fresh-
   conversation publication, a fixed non-private sensitive-delivery canary, the
   first live ordinary approval canary, and only then the first live read. The
   approval canary archives content-free prepare, durable bind, send-start,
   signed commit, exact custom poll ID, owner-DM destination status, authority-
   only suppression, successful canonical owner voter JID, raw `Approve`
   identity, and decision CAS. The first read archives only content-free
   terminal and resolution-attempt evidence and requires exact
   `ordinary_destination_delivered`; ambiguity is consumed and never retried.

Rollback or failure leaves every later stage unauthorized. ADR acceptance does
not land code; landing does not install; installation does not change root
bundles, launch records, socketpair context, configuration, keys, stores,
OpenFGA, OAuth, sessions, pairing, connections, messages, or publication.
Pairing does not connect or send. Enabling does not authorize a canary. A
canary does not authorize Gmail. Only the final exact task-bound owner approval
and policy checks authorize one read.

Choosing Option 2 is an architecture and risk decision only. This ADR and its
engineering work authorize no root/bundle/config/key/store/OpenFGA/OAuth/
session/pairing/connection/message/deployment change, no ownership or ACL
mutation, no launchd change, no process start or restart, no publication, no
credential creation, no account access, and no production operation.

## 14. Alternatives, non-goals, and acceptance

Rejected alternatives include reusing a broad Workspace token; using `gws`, a
skill, browser, Google SDK discovery client, or CLI subprocess; IMAP/App
Passwords; broader/modify/send scopes; model summarization/redaction; ordinary
WhatsApp result delivery; HTML/attachments; multi-account selection; model-
proposed query/message IDs; provider factories/import paths/commands/URLs; a
model-facing or arbitrarily injectable private provider/store/credential path;
shared ordinary/sensitive Node dependency graph; main-YAML/legacy
configuration; gateway-user-writable
staging; `fexecve`/`execveat` on the stated macOS host; or making relay
negotiation a Gmail dependency.

Separate service UIDs or a sandboxed private service are the stronger
confidentiality alternative. The owner chose Option 2 instead on 2026-08-05
with the explicit residual-risk acceptance in section 3. Migrating later is a
new architecture and deployment decision, not an implicit v1 requirement.

Non-goals are mailbox browsing or summaries, thread search, pagination,
history, settings, labels, contacts, background polling, watch/webhooks,
indexing, replay, provider writes, Discord component rollout, physical
byte erasure, native Windows support, and multi-account use.

Implementation acceptance requires all specified product, privacy, process/
channel, OAuth, Gmail, signed-policy/read-only-runtime, approval, three-process
bundle/launch,
lifecycle/epoch, conversation-cache, relay, type, Node, package,
documentation, and regression evidence. It also requires separate security,
product, gateway, policy, runtime, and release approval. This ADR claims none
of those gates have passed.

Unresolved deployment values include the existing gateway UID/GID binding,
concrete launch labels, socketpair/channel identities, OAuth/account/chat/
session/store/model/policy
identities, policy epoch, bundle and artifact digests, adapter/connection/
authority generations, signing and provisioner key IDs, final seal, and exact
launch profile evidence. Conceptual names in this ADR are not deployment
values. Those values must be created and reviewed only at their explicit
activation boundary and may never fall back to ambient state. Separate service
UIDs are neither unresolved nor selected for v1.
