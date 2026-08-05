# ADR: Gmail as Juno's first concrete private-read provider

- **Status:** proposed; implementation and deployment are not authorized
- **Decision revision:** 2026-08-05
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

1. `sender`, from the single `From` MIME header;
2. `to`, from the single `To` MIME header;
3. `cc`, from the single `Cc` MIME header;
4. `subject`, from the single `Subject` MIME header;
5. `date`, from the single `Date` MIME header; and
6. `text_body`, from exactly one eligible non-attachment `text/plain` leaf.

Header values are message claims, not authenticated identities. Missing
allowlisted headers render as a fixed `(not present)` marker. Message and
thread IDs are ephemeral correlation inputs and are never output.

### Owner-facing approval challenge

The stable label is exactly:

> Newest Inbox message — selected headers and plain-text body only

The deterministic v1 challenge template is:

```text
Private-read approval required
Newest Inbox message — selected headers and plain-text body only

One approved read will fetch the newest message in Inbox and output exactly:
sender, to, cc, subject, date, text_body.

It omits attachments, HTML, spam, trash, and additional messages.

Request: {task_display_id}
Generation: {challenge_generation}
Expires exactly: {expiry_rfc3339_utc}

Approve or deny only with the native authenticated approval control attached
to this message. Text replies, copied or forwarded content, quotes, and
reactions do not approve this read.
```

Line endings are LF; labels, punctuation, field order, and blank lines are
fixed UTF-8 bytes. The expiry is a fully specified RFC 3339 UTC instant with
seconds and `Z`. The notification envelope separately contains the exact
ordinary destination binding without displaying a private Gmail identity.

For every send attempt, the host computes a domain-separated HMAC over the
complete rendered UTF-8 challenge bytes and canonical dynamic envelope:
task ID, task display ID, request generation, challenge generation, exact
expiry, destination binding digest, attempt ID, capability descriptor digest,
ordinary adapter instance, account binding, connection epoch, and template
version. This challenge-payload digest is bound to the attempt before send and
must appear in the correlated provider evidence and later owner-decision
evidence. A digest of only the stable label or static template is insufficient.

The owner must use the native authenticated approval control associated with
that exact provider message. Free-form text, a model response, a copied button
payload, a quote, a forward, or a reaction cannot mint approval.

### Content-free owner outcomes

Ordinary and status surfaces never contain Gmail account, query, message IDs,
headers, body, or other private values.

| State | Owner copy | Retry meaning |
| --- | --- | --- |
| Approval required | `Private read awaits your native approval; it expires at {exact time}.` | Use the bound native control. |
| Denied | `Private read denied. No mailbox content was read.` | A later request starts a new task. |
| Expired | `Private-read approval expired. No mailbox content was returned.` | A later request starts a new generation. |
| No match | `No matching Inbox message was available for this approved read.` | Operation is consumed; request again if needed. |
| Malformed or no safe plain body | `The selected message had no safely readable plain-text body.` | Operation is consumed; no content is shown. |
| Gmail, account, or scope failure | `Private read failed at the Gmail account boundary.` | Feature remains closed until healthy. |
| Policy failure | `Private read was not authorized by current policy.` | No Gmail read at the denied stage. |
| Sensitive pre-submit failure | `Sensitive delivery did not start.` | No send occurred; store policy decides a fresh attempt. |
| Ambiguous sensitive post-submit outcome | `Sensitive delivery outcome is unknown; this authorization was consumed.` | Never retry the same authorization or message. |
| Confirmed sensitive delivery | `Sensitive delivery was confirmed.` | Means exact delivery/read/played evidence, not human interpretation. |

`Confirmed sensitive delivery` requires the existing exact correlated
`DELIVERY_ACK`, `READ`, or `PLAYED` sensitive-transport evidence. Ordinary
approval-notification `SERVER_ACK` evidence never upgrades to sensitive
delivery evidence.

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
  WhatsApp, authorization, and sensitive-delivery source foundation is
  deployed. In that source, private-read production composition remains
  dormant/unavailable by construction; source presence does not activate it.
- **Process proof:** launchd label `ai.hermes.gateway` had observed PID `46046`
  running
  `/Users/james/.hermes/hermes-agent/venv/bin/python -m hermes_cli.main gateway run --replace`,
  with process start time `Tue Aug 4 14:14:38 2026`. The launch command has no
  explicit profile flag, so the live runtime profile was not verified by this
  observation and must not be inferred as `juno`.
- **Absent or unverified active state:** no evidence established an active
  Gmail private-read composition, dedicated OAuth client/token, exact granted
  scope, Gmail account binding, OpenFGA service/model/policy, root-owned
  sensitive bundle, paired sensitive session, or published Juno-only tool.
- **Externally asserted facts:** any claim about provider-console state,
  account ownership, launchd environment, connector deployment, or live
  transport pairing that is not in the source/process proof above remains an
  operator assertion until separately evidenced.

The reviewed WIP foundation is not an implementation PASS. In particular,
[`compose_trusted_private_read_services()`](../../gateway/trusted_private_read_host.py)
returns `None` in the reviewed source, so enabled configuration cannot produce
a host. The proposed changes below replace that dormant boundary only after
implementation review.

## 3. Privacy and threat contract

### Principals and fixed boundaries

The trusted principals are the exact authenticated requester scope, one
gateway process and coordinator generation, one dedicated Gmail Desktop OAuth
client/grant and expected account, one pinned local OpenFGA 1.18.2 deployment,
one separately approved root-owned sensitive bundle, and distinct ordinary
and sensitive WhatsApp accounts/processes/sessions.

Display names, aliases, ambient profiles, global Google credentials, service
self-reports, relay envelope claims, model text, and environment-selected
accounts are never authority. Root or kernel compromise, Google compromise,
and a same-process memory-forensic attacker are outside the v1 guarantees
stated below.

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

The following are code maxima; the closed configuration may only reduce them.
The effective values are descriptor-bound. Crossing a cap fails rather than
truncating silently.

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

### Honest in-process memory guarantee

V1 guarantees bounded logical reachability, not physical zeroization. Private
content and tokens have the shortest practical lifetimes; references are
released explicitly in `finally` paths; controlled mutable buffers are wiped
where the application truly owns them. No application persistence, logs,
traces, model/tool/session/history/audit/policy/task content, or retained task
results are permitted.

V1 does not claim that immutable Python `bytes`/`str`, HTTPX request/response
objects, TLS buffers, exception allocator storage, or CPython allocator copies
are physically erased. A same-process memory-forensic attacker is outside this
plaintext-erasure guarantee. If physical erasure becomes a requirement,
OAuth/fetch/parse/render must move into a killable isolated process and the
current `Awaitable[str]` host boundary must be redesigned so plaintext never
crosses back as a Python string.

`GmailMessageReadDto` is a slots-based class with `repr=False`, a fixed
redacted `__repr__` and `__str__`, and no dataclass `asdict`, pickle, or copy
helpers where feasible. Privacy tests cover `repr(dto)`, `str(dto)`, container
reprs, attempted pickle/copy, and all exception/task surfaces.

### Exception and cancellation hygiene

The sensitive adapter never calls `raise_for_status()` and never rethrows an
HTTPX, OAuth, provider, JSON, MIME, renderer, or sensitive-send exception. A
private inner async frame owns request, response, token, body, parser, DTO, and
render references. It catches every failure, manually maps the HTTP status and
failure class to a closed non-private code, closes streams, releases all
request/response/token/body references, wipes controllable buffers, and
completes bounded mandatory cleanup.

Only after the private exception frame has exited does an outer wrapper raise
a fresh fixed `PrivateReadProviderFailure(code)` from `None`. Public error text
is selected from a closed constant map and contains no upstream text.

For cancellation or another `BaseException`, the inner frame records only a
non-private control-flow kind, completes mandatory shielded bounded cleanup,
exits the exception frame, and then recreates cancellation/control flow from
outside it without retaining or re-raising the original exception graph. A
fresh `asyncio.CancelledError()` or fixed control exception is raised from
`None`. Cleanup failure permanently revokes host health and returns only a
fixed content-free diagnostic.

Tests recursively traverse exception cause, context and tracebacks and inspect
traceback locals, suspended/completed coroutine frames, HTTPX request/response
objects, live tasks, task callbacks, and completed task results. Sentinels must
be absent after success, every mapped failure, cancellation, and shutdown.

## 4. Requester, discovery, and durable capability identity

### Closed requester scope

The closed configuration contains exactly:

```yaml
requester:
  gateway_profile: juno
  agent_identity: <exact reviewed Juno agent identity>
  platform: whatsapp
  ordinary_account_binding: <exact ordinary account binding>
  owner_sender: <exact authenticated owner sender>
  source_chat: <exact ordinary source chat>
  source_thread_sentinel: <exact no-thread or thread sentinel>
  authenticated_provenance_version: <exact code-owned provenance/version>
```

Unknown or missing requester keys fail parsing. Every value is sealed into the
composition and requester-scope digest. The gateway checks all seven values at
authenticated event bind and again when durably creating the task. Wrong
profile, agent, platform, account, sender, chat, thread sentinel, provenance,
or generation fails before model invocation, tool invocation, task mutation,
or authorization mutation. No event-global or ambient profile may substitute.

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
conversation/session generation after successful host publication. Existing
conversations remain unavailable, preserving prompt-cache identity.

Tests prove: absent host means absent schema; a healthy published Juno
generation gets the exact one-value enum and exact non-private purpose; other
profiles get no schema; old generations do not gain it; replacement requires a
fresh generation; and schema/instruction bytes are stable across turns.

### Canonical descriptor and fingerprints

The immutable operation registry contains one closed descriptor. Its canonical
bytes include, or domain-separated HMAC-bind, all of:

- descriptor version, capability ID, operation version, provider kind, and
  adapter implementation identity/version/digest;
- Gmail account-binding HMAC and exact query HMAC for `in:inbox`;
- the ordered field tuple `sender,to,cc,subject,date,text_body`;
- every exact effective read/network/parser/render limit;
- the exact stable approval-label digest and challenge-template version;
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
affected task/attempt rows, applies the following status matrix, preserves the
decision and resolution record, and atomically refreshes the mutable-state HMAC
and audit-chain head/count for every mutation:

| Existing state | Reconciled task state | Notification treatment |
| --- | --- | --- |
| Pre-side-effect pending or approval state | terminal `descriptor_mismatch` | Unstarted attempts become superseded; definite pre-submit failures remain failed. |
| `claimed` or any post-read uncertainty | terminal `failed_consumed` | Send-start-fenced attempts become ambiguous unless exact terminal evidence already exists. |
| Decision recorded, resolution pending | Decision remains audit-complete; task terminalizes per side-effect state | Resolution attempt becomes superseded, failed, or ambiguous from its own send-start fence. |
| Terminal task | Unchanged except verified audit repair is forbidden | Existing evidence remains immutable. |

No generic `cancel()` transition is reused where its accepted states or reason
codes do not fit. A mismatch can never revive or requeue an approval. Dequeue,
pre-claim, and pre-private-read checks use the same exact descriptor matcher.

## 5. Ordinary approval challenge and resolution

### Dedicated Baileys operation

`OrdinaryWhatsAppApprovalAuthority` uses a dedicated code-owned ordinary
Baileys approval-notification operation, not generic `SendResult`. The
implementation pins and audits the exact Baileys rc14 event semantics. Where
the API supports it, it pre-reserves or otherwise knows the exact provider
message ID before submission, arms one bounded listener before send, and then
correlates:

- notification kind (`approval_challenge` or `approval_resolution`), attempt
  ID, task ID, request/challenge generation, and exact payload digest;
- provider message ID, exact destination, ordinary adapter instance, ordinary
  account binding, and connection epoch;
- exact provider signal, evidence ID, and observation time; and
- the code-owned ordinary bridge/version and authenticated event provenance.

For these non-private notifications only, a correlated Baileys `SERVER_ACK`
may be classified narrowly as `provider_server_accepted`. It is not delivery,
read, display, human receipt, or approval. If the pinned rc14 bridge cannot
safely pre-correlate and observe the exact `SERVER_ACK`, this capability stays
disabled.

HTTP 200, submission resolution, `SendResult.success`, a locally generated or
returned message ID, sender-companion echo, unknown status, disconnect,
timeout, or late signal cannot mint acceptance. An ambiguous post-submit
outcome consumes that notification attempt and message ID; it is never retried.
Where the task state permits another challenge, the store creates a new
challenge generation and attempt, never a replay of the old attempt.

The store is the sole attempt-ID allocator. It derives the bounded attempt ID
deterministically as a domain-separated HMAC of task ID, notification kind,
request generation, challenge generation, and monotonically assigned attempt
ordinal. Challenge and resolution kinds use distinct domains; an ID cannot be
reused across a generation or notification kind.

### Challenge state machine

The deterministic challenge payload is the template in section 1. The store
reserves the attempt ID, message correlation material, generation, exact
expiry, destination digest, and challenge-payload HMAC atomically before send.

- A definite failure before the send-start fence may create a new attempt in
  the same generation under bounded store policy.
- After the send-start fence, lack of exact `SERVER_ACK` is ambiguous. The
  attempt is consumed; only a new challenge generation may proceed where the
  task has not expired and the state machine explicitly allows it.
- Exact provider-server acceptance makes the native control eligible. It does
  not approve the task.
- Expiry is checked at provider evidence, native decision, atomic decision
  commit, pre-claim, and pre-private-read.

A decision must be a native authenticated control/reply whose gateway profile,
agent, platform, adapter instance, account, connection epoch, sender, chat,
thread sentinel, source provider message ID, challenge attempt, task,
generation, nonce/control ID, payload digest, and provenance/version all match.

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
binding, ordinary adapter/account/epoch, decision-evidence digest, descriptor
digest, and template version. Resolution expiry is deterministically the
decision-recorded instant plus the code-fixed 60-second notification window.
Resolution uses the same pre-armed exact `SERVER_ACK` contract. Definite
pre-submit failure may create a fresh resolution attempt before that expiry;
expiry terminalizes an unstarted/pre-submit resolution attempt, while an
attempt past its send-start fence remains ambiguous. An ambiguous post-submit
outcome never retries the same attempt/message. The durable decision remains
audit-complete regardless of notification outcome. A late or unknown signal
cannot change the decision or pop pending native-control state.

Pinned Node contract tests exercise the actual reviewed ordinary bridge and
rc14 event adapter, including listener-before-send ordering, ID reservation,
all correlation dimensions, late events, disconnect, timeout, duplicate
events, and evidence classification. Python mocks alone are insufficient.

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

Only the six canonical fields enter the slots/redacted DTO. The renderer uses
fixed ASCII field labels, field order, LF separators, no Markdown, HTML,
linkification, locale, model, or adaptive behavior, and asserts the final
4,096-byte cap.

## 7. Exact task-bound OpenFGA contract

`LocalOpenFgaPrivateReadPdp` targets exactly OpenFGA 1.18.2 at the code-fixed
loopback store and exact configured authorization model. Startup verifies the
service version, store, model bytes/digest, policy version/digest, and
owner-policy epoch without creating or changing any of them.

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

Tests mutate every contextual binding independently and require deny/failure,
prove the exact two tuples and condition on every call, prove no contextual
standing grant, and prove no field/batch shortcut exists.

## 8. Sensitive delivery executable identity on macOS

Live macOS 26.5.2 Python exposes neither `os.fexecve` nor `os.execveat`.
MacOS v1 therefore uses an explicit OS immutability boundary, not a path
recheck or gateway-user-writable staging claim.

At a separately approved deployment step, the sensitive Node executable,
launcher, manifest, verifier, source, package/lock metadata, and complete
`node_modules` closure are installed into a versioned content-addressed bundle
under a code-owned root such as:

```text
/Library/Application Support/Hermes/private-read-bundles/sha256-<bundle-digest>/
```

All ancestors and bundle directories are root-owned and not group/world
writable. Every entry is non-symlinked, has the reviewed type, mode and link
count, is root-owned, is not writable by the gateway OS user, and is covered by
an independently reviewed manifest/hash closure. Regular files are one-link;
unknown files and mount/path substitution fail. Code/config can select only an
allowlisted bundle digest/version, never an arbitrary command, executable,
module, or path.

The host independently opens and hashes the exact root-owned bundle, verifies
the manifest, verifier, source, pinned Node binary, Baileys rc14 identity, and
full dependency closure, and constructs the registration command solely from
that verified bundle. It rechecks ownership, path ancestry, types, modes,
links, manifest, and hashes immediately before spawn. Root-owned immutability
then prevents the gateway user from replacing verified bytes between check and
execution under the v1 threat model. Root and kernel compromise are outside
this boundary.

The root-owned launcher again verifies the manifest, verifier, source, pinned
runtime, package/lock identity, and complete dependency closure before any
dynamic import. Copying or staging into a gateway-user-writable directory does
not provide verified-to-executed identity and is not part of this design.

No bundle installation occurs during engineering, normal startup, or this ADR
revision. Installation, verification, rollback, and removal require later
explicit root-authorized deployment and real proof. Unit tests use a
production-owner predicate plus an explicit test-only expected-owner seam;
deployment acceptance additionally requires a real root-owned bundle probe.

Production startup fails before OAuth/OpenFGA/session provisioning on native
Windows for v1 with an accurate “root-owned macOS sensitive bundle required;
native Windows unsupported” status, unless a separate ADR approves an
ACL-aware verified-to-executed equivalent.

Ordinary and sensitive account/profile/session/process/socket/dependency/
queue/logger identities remain distinct. Pairing is absent from production
startup and uses alphanumeric code only. Sensitive post-submit ambiguity burns
the authorization; no result retry occurs.

## 9. Async composition, publication, and cleanup

### Real initialization seam

Synchronous `compose_trusted_private_read_services()` performs only inert,
exact, code-owned construction. It returns a
`TrustedPrivateReadHostServices` whose required `initialize`/`start_checks`
callable is async and whose `close` callable owns every constructed cleanup
slot. Constructors do no network, SQLite, session, subprocess, socket, path
creation, OAuth, Gmail, or OpenFGA work.

The exact call site is the existing async
`GatewayRunner._start_trusted_private_read_host()` in
[`gateway/run.py`](../../gateway/run.py). The runner owns the returned services
until it explicitly transfers ownership into `TrustedPrivateReadGatewayHost`.
It calls and awaits `services.initialize()` first. If service initialization,
host construction, host preparation, or publication fails before transfer,
the runner directly awaits `services.close()`; it never relies on a host that
was not constructed to clean them up.

Async initialization runs in this order:

1. verify platform support and the root-owned sensitive bundle before any
   credential, store, session, or service access;
2. verify closed config, key, allowlist, OAuth client/token, session-path
   separation, exact requester/descriptor/composition seals, and fixed
   authorities without creating paths;
3. verify pinned local OpenFGA version/store/model/policy/epoch read-only;
4. perform the initial OAuth exchange or refresh, require the exact scope
   response, and verify the Gmail profile identity without reading a message;
5. verify the exact ordinary adapter/account/connection/provenance and offline
   sensitive session/account readiness without opening a sensitive socket;
6. open the authorization store, run the coordinator-fenced descriptor
   reconciliation transaction, acquire the singleton coordinator, and create
   the worker; and
7. recheck every seal, descriptor, generation, identity, and health predicate
   and mark the unpublished composition prepared.

### Atomic publication

After preparation and host ownership transfer, one process-global async
publication lock and monotonic generation atomically install all three values:

1. the runner host pointer;
2. the event-authority publication generation; and
3. the service-gated private-read tool runtime used for future conversation
   discovery.

Readers take one immutable publication snapshot. No tool-visible partial
interval exists. Rollback and shutdown acquire the same lock and clear all
three values in one generation change, unpublishing before worker/resource
cleanup. Existing conversation schemas remain byte-stable and do not acquire
the tool mid-conversation.

### Non-discardable cleanup

Cleanup is a bounded, shielded, reverse-order close plan owned by the services.
It records cleanup slots as resources are acquired and attempts every slot even
after an earlier slot fails: tool/event/host unpublish, worker, coordinator,
store, sensitive process group/socket/pipe, ordinary listener, sessions,
HTTP streams/clients, token/DTO/body references, descriptors, and controlled
buffers. Cleanup errors are aggregated only as content-free codes.

Cancellation cannot discard cleanup. The runner/host starts one owned cleanup
task, shields and awaits it within a fixed bound, and proves each absence or
closure. Failure or timeout leaves all three publications absent and marks
health permanently failed. The original private exception graph is not
retained when cancellation/control flow is recreated.

### Exact proposed file changes

- [`gateway/trusted_private_read_host.py`](../../gateway/trusted_private_read_host.py):
  add the required async service initialization seam; implement inert exact
  composition, explicit ownership transfer, prepared-host start, the
  coordinator-fenced reconciliation call, generation-aware event authority,
  and reverse-close ownership.
- [`gateway/run.py`](../../gateway/run.py): make
  `_start_trusted_private_read_host()` own services until transfer, await async
  initialization in the safe order, close services directly on pre-transfer
  failure, and publish/unpublish the host pointer and generation under the one
  process-global lock.
- [`tools/private_read_request_tool.py`](../../tools/private_read_request_tool.py):
  materialize the exact enum schema from the immutable registry before a fresh
  conversation, install/clear its runtime only through the publication
  transaction, reject generation drift, and preserve old conversation tool
  bytes.

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

## 11. Closed configuration shape

The future schema rejects unknown, missing, duplicate, or wrongly typed keys.
Placeholders are deployment values; no real account, token, session, store, or
chat identifier appears here.

```yaml
trusted_private_read:
  version: 3
  enabled: false
  state_dir: <canonical absolute owner-only directory>
  key_file: <canonical absolute owner-only 0600 regular file>
  composition_seal_file: <canonical absolute owner-only 0600 regular file>

  requester:
    gateway_profile: juno
    agent_identity: <exact reviewed Juno agent identity>
    platform: whatsapp
    ordinary_account_binding: <exact ordinary account binding>
    owner_sender: <exact authenticated owner sender>
    source_chat: <exact ordinary source chat>
    source_thread_sentinel: <exact no-thread or thread sentinel>
    authenticated_provenance_version: <exact code-owned provenance/version>

  gmail:
    kind: gmail_v1
    oauth_client_file: <canonical absolute owner-only 0600 regular file>
    oauth_token_file: <canonical absolute owner-only 0600 regular file>
    expected_profile_email: <exact provider-canonical Gmail identity>
    required_scopes:
      - https://www.googleapis.com/auth/gmail.readonly

  capability:
    capability_id: gmail.newest_inbox_message.read
    operation_version: 1
    approval_label: Newest Inbox message — selected headers and plain-text body only
    query: in:inbox
    fields: [sender, to, cc, subject, date, text_body]

  openfga:
    version: 1.18.2
    store_id: <reviewed local store identity>
    authorization_model_id: <reviewed model identity>
    policy_version: <reviewed policy version>
    policy_sha256: <reviewed lowercase SHA-256>
    owner_policy_epoch: <reviewed monotonic epoch>

  sensitive_delivery:
    platform: whatsapp
    profile: <exact sensitive profile>
    account: <exact sensitive provider account>
    destination_chat: <exact sensitive destination>
    destination_thread: <exact thread sentinel>
    session_dir: <canonical absolute sensitive session directory>
    bundle_version: <reviewed root-owned bundle version>
    bundle_sha256: <reviewed lowercase SHA-256>

  limits:
    approval_ttl_seconds: 300
    connect_seconds: 2.0
    write_seconds: 2.0
    read_seconds: 5.0
    pool_seconds: 1.0
    request_total_seconds: 8.0
    private_read_total_seconds: 20.0
    oauth_response_bytes: 32768
    gmail_profile_or_list_bytes: 65536
    gmail_message_bytes: 262144
    mime_depth: 8
    mime_parts: 32
    encoded_candidate_bytes: 65536
    decoded_candidate_bytes: 16384
    text_body_bytes: 3072
    rendered_plaintext_bytes: 4096
```

Config cannot supply a URL, provider factory, import path, callable, command,
executable, Node path, module, arbitrary query, alternate field, or approval
copy. The parser requires the exact v1 capability values above rather than
treating them as general extension points. Code fixes Gmail/OAuth authorities,
OpenFGA loopback authority, selectors, templates, relation map, and bundle root.

## 12. Verification and implementation plan

No gate below is claimed passing. Implementation begins only after this ADR is
accepted and proceeds in small reviewed slices.

### Product and generic authorization contracts

Tests first fix the exact capability/query/label/fields, requester binding,
descriptor/HMAC domains, cache-stable schema discovery, generation replacement,
whole-descriptor reconciliation matrix, and two unrelated synthetic provider
adapters. They prove no Gmail branch enters generic authorization and no
query/account plaintext enters model, schema, store, policy, audit, or ordinary
notifications.

### Gmail and OAuth boundary

Tests cover both initial and refresh responses with exact scope, all missing/
duplicate/extra/case variants, dedicated client/grant binding, account drift,
fixed methods/authorities/paths/query/selectors/`prettyPrint=false`, redirects,
stream caps, response allocation order, duplicate JSON, MIME budgets,
incidental receipt, no ineligible decode or attachment fetch, DTO repr/str,
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
standing-policy ownership, and all independent mutation failures. Approval
tests cover exact deterministic challenge/resolution payloads, atomic decision
enqueue, pre-armed rc14 `SERVER_ACK`, native controls, retry/ambiguity/expiry,
and pinned Node behavior. Sensitive tests cover the root-owner predicate,
manifest closure, pre-spawn recheck, test-owner seam, real deployment probe,
account/session separation, and exact sensitive ACK meanings. Lifecycle tests
inject `BaseException` and cancellation at every construction, initialization,
transfer, publication, read, send, unpublish, and cleanup slot. Relay tests
prove Discord components are inert and Juno is independent.

### Reproducible Python type gate

Type reports record both the parent/base and candidate. For the reviewed WIP:

```text
source commit: 49d78bdc915e9e2c3ff78d7d4a3a7074ddb6ac85
source parent: 0595c3816d9d67a3c409f7671520cadd4c2d32a8
tool: ty==0.0.21
```

The exact changed-Python manifest from that parent is:

```text
gateway/platforms/base.py
gateway/relay/adapter.py
gateway/relay/ws_transport.py
gateway/trusted_private_read_host.py
tests/gateway/relay/test_relay_interactive.py
tests/gateway/relay/test_relay_passthrough.py
tests/gateway/relay/test_relay_per_platform_caps.py
tests/gateway/relay/test_ws_callback_dispatch.py
tests/gateway/relay/test_ws_transport.py
tests/gateway/test_active_principal_lifecycle.py
tests/gateway/test_trusted_private_read_host.py
tests/test_install_ps1_whatsapp_home_and_node_contract.py
```

Release verification creates two isolated owner-only source trees and two
owner-only tool/cache/home/temp environments, one at the parent and one at the
candidate. It regenerates the manifest from Git in each comparison workflow,
aborts if the manifest is empty, invokes the canonical lock-backed checker as
`uvx --from ty==0.0.21 ty check -- <exact manifest>`, and archives normalized
diagnostics with checkout prefixes, volatile paths, and ordering removed in a
specified deterministic way. Candidate-only diagnostics are the set difference
`normalized(candidate) - normalized(parent)`; raw totals are reported
separately and are never substituted for that difference.

The previously supplied candidate-only target is 26. It must be regenerated
and archived before implementation acceptance; this ADR does not certify it.
No baseline suppression, exclusion, inline ignore, empty-manifest invocation,
or hardcoded missing `.venv/bin/ty` is permitted. Command-scoped
`UV_CACHE_DIR`, `XDG_CACHE_HOME`, tool home, and temp paths are owner-only and
destroyed after evidence capture.

### Reproducible Node, package, docs, and test gates

All ordinary and sensitive bridge release tests run through the exact reviewed
deployment Node executable from the candidate bundle, never ambient `node`.
The harness asserts `process.execPath`, exact version, and executable SHA-256
before tests. The exact reviewed package manager entry point is also invoked
through that Node executable.

Each ordinary and sensitive package starts from a clean owner-only directory,
runs frozen/offline `npm ci` against the reviewed package and lock files,
rejects lock mutation or network fallback, and records package/lock hashes plus
the installed-tree/manifest identity. A separate `npm audit` is required for
both packages with the exact reviewed executable/package-manager identity and
an archived result; the release record distinguishes the intentionally online
audit from offline installation. No ambient Node/npm evidence is accepted.

Canonical and localized documentation that describes the root Hermes runtime
must agree with the root engine requirement `Node >=22.22.0`, including
English, Spanish, Chinese, and any other translated copies found by
repository-wide search.
Independent product/skill/package engine requirements are preserved and not
mechanically overwritten. Documentation validation records every changed
runtime claim and its owning package.

Focused tests and then the supported full repository suite run with synthetic
identities only. No real Gmail, OpenFGA, WhatsApp, account, token, credential,
session, or live service is used during engineering. Privacy sentinels are
scanned across logs, exceptions and traceback locals, tasks/coroutines,
request/response objects, SQLite/WAL/journal, audit/policy bodies, files,
model/session/memory surfaces, argv/environment, caches, and result objects.

## 13. Deployment activation boundaries

These approvals are separate, ordered, and non-transitive. Approval of one
does not imply any later action:

1. Product accepts the exact query `in:inbox`, stable label, six ordered fields,
   requester scope, challenge/resolution templates, and outcome copy.
2. Land the separately reviewed implementation commit.
3. Install the candidate default-off.
4. Separately install and review the versioned root-owned sensitive bundle,
   including real ownership/immutability/hash/rollback proof.
5. Create the dedicated Gmail Desktop OAuth client/token, satisfy the current
   restricted-scope policy, and prove the exact `gmail.readonly` grant only.
6. Start/provision OpenFGA 1.18.2 and its separately owned standing policy.
7. Provision/pair sensitive WhatsApp by alphanumeric code only; QR is absent.
8. Connect and verify ordinary and sensitive transports independently.
9. Generate and review the final closed configuration/composition seal.
10. Authorize `enabled: true`, the exact Juno profile launch configuration,
    and the planned gateway restart.
11. After restart, verify content-free health and Juno-only tool publication in
    a fresh conversation/session generation; old generations remain unchanged.
12. Send the exact approved non-private canary through sensitive delivery.
13. Obtain the first exact native approval and perform the first private Gmail
    read.

Rollback or failure leaves later stages unauthorized. Product approval does
not land code. Code landing does not install. Installation does not install a
root bundle. Bundle installation does not authorize OAuth. OAuth does not
authorize OpenFGA or a read. Pairing does not connect or send. Enabling does not
authorize a canary. A canary does not authorize Gmail. Only the final exact
task-bound owner approval and policy checks authorize one read.

## 14. Alternatives, non-goals, and acceptance

Rejected alternatives include reusing a broad Workspace token; using `gws`, a
skill, browser, Google SDK discovery client, or CLI subprocess; IMAP/App
Passwords; broader/modify/send scopes; model summarization/redaction; ordinary
WhatsApp result delivery; HTML/attachments; multi-account selection; model-
proposed query/message IDs; provider factories/import paths/commands/URLs; a
gateway-user-writable sensitive staging directory; `fexecve`/`execveat` on the
stated macOS host; or making relay negotiation a Gmail dependency.

Non-goals are mailbox browsing or summaries, thread search, pagination,
history, settings, labels, contacts, background polling, watch/webhooks,
indexing, replay, provider writes, Discord component rollout, physical
in-process byte erasure, native Windows support, and multi-account use.

Implementation acceptance requires all specified product, privacy, OAuth,
Gmail, policy, approval, sensitive bundle, lifecycle, cache-stability, relay,
type, Node, package, documentation, and regression evidence. It also requires
separate security, product, gateway, policy, runtime, and release approval.
This ADR claims none of those gates have passed.

Unresolved deployment values include every real OAuth/account/chat/session/
store/model/policy identity, owner-policy epoch, root bundle digest, adapter
connection identity, final seal, and exact launch profile evidence. They must
be created and reviewed only at their explicit activation boundary and may
never fall back to ambient state.
