# ADR: Gmail as Juno's first concrete private-read provider

- **Status:** proposed; implementation and deployment are not authorized
- **Decision snapshot:** 2026-08-04
- **Source commit:** `49d78bdc915e9e2c3ff78d7d4a3a7074ddb6ac85`
- **Source tree:** `c88ba9d705453561678b4e8ba2b501b4ff55a8bd`
- **Audience:** product, security, gateway, and release reviewers

This ADR describes a future implementation. The source tree above is a
rejected, undeployed WIP and is not deployable. Nothing in this ADR authorizes
OAuth consent, mailbox access, OpenFGA provisioning, WhatsApp pairing, a
service start, or a private read.

## 1. Decision and status

### Decision

Juno's first code-owned private-read provider will be Gmail. Version 1 will:

- bind one explicitly configured, provider-canonical Gmail account identity;
- use a new, dedicated OAuth client and token whose exact granted scope set is
  only `https://www.googleapis.com/auth/gmail.readonly`;
- expose only reviewed, fixed-query `gmail.latest_message.read` capabilities;
- read one provider-selected first matching message, with no pagination;
- return only fixed headers and a bounded `text/plain` body;
- require a fresh owner approval and two OpenFGA checks for every read; and
- deliver the result only through the separately paired sensitive WhatsApp
  transport.

The initial deployment target is James's personal Gmail account. The code is
generic for one reviewed Gmail account and must compare the live
`users.getProfile('me').emailAddress` value with the exact configured identity.
There is no ambient, default, or multi-account selection.

The feature remains default-off. A complete configuration is necessary but is
not sufficient: startup must prove every local identity and dependency before
publishing the tool.

### What exists, and what does not

- **Active production foundation.** The gateway lifecycle, authenticated
  inbound event model, ordinary WhatsApp adapter, session isolation, durable
  authorization contracts, and sensitive-delivery state machine are the
  foundation this design extends. Their presence does not make Gmail reads
  active.
- **Deployed but dormant private-read foundation.** Per the product snapshot
  supplied for this decision, the private-read request tool, authorization
  store/contracts, and sensitive-delivery components are present but have no
  production composition. They are unavailable unless one exact host runtime
  is published.
- **Rejected WIP.** In the exact source tree, `compose_trusted_private_read_services`
  unconditionally returns `None`; enabled configuration therefore still cannot
  activate the host. The WIP also verifies a launcher in configuration without
  binding that artifact to the later `SensitiveDeliveryTransportRegistration`,
  performs some store/service work before the final artifact check, accepts a
  service-reported transport identity, and consumes a relay
  `authenticatedUserId` field for which this repository does not prove a
  connector producer. The candidate also has 26 changed-file `ty` diagnostics,
  and English Node documentation disagrees with the root
  `>=22.22.0` engine requirement.
- **Proposed composition.** The concrete classes and startup transaction in
  this ADR replace the dead composition only after tests and review.
- **Later explicit boundaries.** OAuth creation/consent, OpenFGA service and
  policy provisioning, sensitive WhatsApp pairing, transport connection, a
  canary, and the first Gmail read remain separate approvals.

Relevant repository contracts are
[`trusted_private_read_host.py`](../../gateway/trusted_private_read_host.py),
[`private_read_authorization.py`](../../gateway/private_read_authorization.py),
[`authorization_tasks.py`](../../gateway/authorization_tasks.py),
[`authorization_contracts.py`](../../gateway/authorization_contracts.py),
[`authorization_sensitive_delivery.py`](../../gateway/authorization_sensitive_delivery.py),
[`sensitive_delivery.py`](../../gateway/sensitive_delivery.py), and
[`run.py`](../../gateway/run.py). The current operator descriptions are
[`trusted-private-read-host.md`](../trusted-private-read-host.md) and
[`relay-connector-contract.md`](../relay-connector-contract.md).

### Provider facts used by this decision

The design relies on these primary-source contracts:

- Gmail
  [`users.messages.list`](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/list)
  is `GET /gmail/v1/users/{userId}/messages`. Its `q` parameter uses Gmail
  search syntax; `maxResults` is provider-bounded (currently at most 500); and
  list entries contain only `id` and `threadId`, so message content requires a
  separate get call. It supports `gmail.readonly`.
- Gmail
  [`users.messages.get`](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get)
  retrieves one exact message ID with an explicit `format`, and supports
  `gmail.readonly`.
- Gmail
  [`users.getProfile`](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users/getProfile)
  returns the authenticated Gmail profile's provider-canonical `emailAddress`.
- Google's
  [OAuth scope catalog](https://developers.google.com/identity/protocols/oauth2/scopes)
  describes `gmail.readonly` as permission to view email messages and settings.
  That provider credential is broader than Juno's code-owned operation, so the
  adapter restrictions below remain essential.
- OpenFGA's
  [consistency documentation](https://openfga.dev/docs/interacting/consistency)
  says `HIGHER_CONSISTENCY` skips the query cache and reads the database
  directly. It is a request preference, not a server-issued consistency token,
  proof of linearizability, or attestation. The same page describes a
  Zanzibar-style consistency token as future work, not a current response.

## 2. Threat model and exposure contract

### Principals, processes, and boundaries

The exact principals are:

- the authenticated owner on Juno's one configured ordinary WhatsApp account,
  chat, sender, and gateway profile;
- the gateway process and its single private-read coordinator lease;
- Juno's configured requester agent/profile for the active logical event;
- one dedicated Gmail OAuth client/token and one expected Gmail profile;
- one pinned local OpenFGA 1.18.2 service, store, authorization model, and
  policy revision;
- one independently verified sensitive-launch bundle and pinned Node runtime;
  and
- one separately provisioned sensitive WhatsApp account, session, process,
  socket, and destination.

The ordinary WhatsApp account is an approval source and notification
destination only. Gmail is the private source. The sensitive WhatsApp account
is the only private destination. The model, ordinary WhatsApp result path,
relay connector, session history, memory system, logs, and authorization store
are not private destinations.

Configuration identities are exact provider or gateway identifiers, never
display names. Account aliases, inferred defaults, environment-selected
profiles, globally authenticated CLIs, and service self-reports cannot choose
an identity.

### Allowed private output in v1

One approved operation may return exactly:

- the one message Gmail returns first for the fixed reviewed query when called
  with `maxResults=1` and `includeSpamTrash=false`;
- canonical DTO fields `sender`, `to`, `cc`, `subject`, and `date`, sourced only
  from the corresponding `From`, `To`, `Cc`, `Subject`, and `Date` MIME
  headers; and
- one bounded, non-attachment `text/plain` MIME leaf.

The sender and recipient fields are message header claims, not proof that Gmail
authenticated the human identity they name. The deterministic renderer labels
them as message headers and does not promote them to authorization evidence.

The list result's message ID is used ephemerally for the required
`messages.get` call. The thread ID is type-checked for list/get agreement but is
not required for delivery. Neither ID is included in the v1 rendered result.
Adding either later requires an explicit field allowlist and policy change.

For this ADR, “latest” is the product name for the single first result returned
by Gmail's list operation for the exact query. The cited method documents the
query and response shape but does not promise a total ordering. The adapter
must not invent a second client-side ordering rule or claim snapshot stability
across concurrent mailbox changes.

### Forbidden access and output

Version 1 must not read, emit, or act on:

- attachments, attachment IDs for retrieval, or attachment bytes;
- HTML rendering or execution, scripts, styles, tracking pixels, links, or any
  remote content fetch;
- labels, settings, contacts, history, mailbox totals, snippets, or thread
  contents beyond fields structurally required to select and parse the message;
- spam or trash, a second match, a next page, an empty/broad mailbox dump, or
  more than one Gmail account;
- Gmail send, modify, delete, draft, import, insert, archive, mark, or label
  operations; or
- model summarization, model redaction, or any model-visible transformation of
  the private body.

Private plaintext must never enter model context, prompts, tool results,
ordinary WhatsApp sends, logs, exception text or chains, traces, metrics,
audit/task/OpenFGA metadata, SQLite, command arguments, environment variables,
files, caches, indexes, replay data, session history, memory, checkpoints, or
completed background-task results.

### Exact bounds

The following are hard code maxima. Configuration may only make them smaller.
Crossing any bound fails the operation; it does not truncate provider input
silently.

- Fixed Gmail query: 512 UTF-8 bytes; one non-empty line; no NUL, C0 controls,
  DEL, leading/trailing whitespace, or invalid Unicode. It is passed exactly as
  reviewed after URL encoding. Juno performs no semantic rewrite because Gmail
  defines the search syntax.
- Provider message and thread IDs: 256 ASCII bytes each, using only the
  provider-observed values. No model-proposed ID exists in v1.
- Request URL: fixed HTTPS authority and code-owned path templates; 2 KiB after
  percent encoding. Authorization and content headers: at most 32 headers,
  8 KiB aggregate, and 2 KiB per value.
- OAuth response: 32 KiB. Profile and list responses: 64 KiB each. Message-get
  response: 256 KiB. Bodies are streamed and aborted at one byte over the cap.
- JSON: UTF-8 only, duplicate keys rejected at every object, maximum nesting
  depth 32, maximum 256 aggregate scalar/container entries, integers within
  signed 64-bit range, and strict documented types. Unknown keys fail closed
  unless listed as an explicitly ignored documented Gmail field.
- MIME: maximum depth 8, 32 total parts, 64 headers per part, 64-byte header
  names, 2,048-byte decoded header values, and 8 KiB aggregate allowlisted
  header text. A `message/rfc822` part is opaque and never traversed.
- MIME data: maximum 64 KiB aggregate base64url text across inspected
  non-attachment candidates, 16 KiB aggregate decoded candidate bytes, and
  exactly one eligible `text/plain` leaf. Base64url must be canonical and
  strictly decodable. The selected body must be strict UTF-8 and at most 3,072
  bytes after CRLF-to-LF normalization. NUL and disallowed controls fail.
- Rendered result: at most the existing
  `MAX_SENSITIVE_PLAINTEXT_BYTES` of 4,096 UTF-8 bytes, including fixed labels
  and separators. Header injection characters fail rather than being escaped
  ambiguously.
- Network time: connect 2 seconds, TLS handshake within the connect budget,
  write 2 seconds, read 5 seconds, pool 1 second, and 8 seconds total per OAuth,
  profile, list, get, or OpenFGA request. A complete private read has a 20-second
  outer deadline.
- Redirects: zero for OAuth, Gmail, and OpenFGA. Any 3xx is failure.

Only TLS validated against the process's reviewed CA configuration is allowed
for Google. Plain HTTP is allowed solely for the code-fixed OpenFGA loopback
endpoint. Proxy discovery, `.netrc`, ambient credentials, and environment
trust are disabled for these clients.

Empty results, multiple list entries despite `maxResults=1`, a next-page-only
response, list/get ID disagreement, an absent safe `text/plain` leaf,
duplicate allowlisted headers, malformed MIME/base64/JSON, unknown response
shape, provider error, cancellation, timeout, redirect, or oversize response
all fail closed before sensitive delivery. Attachments and HTML parts within an
otherwise valid bounded MIME tree are counted but ignored and never decoded.

### Plain-language privacy journey

The model may ask only for a named, pre-reviewed capability. It cannot supply a
Gmail query. The owner receives a private-result-free approval message on the
ordinary account. If the authenticated owner replies to that exact challenge,
OpenFGA approves every requested field twice, and the identities remain fresh,
the gateway reads one message. The text exists briefly in the Gmail adapter,
the parent worker, and the isolated sensitive-delivery pipe/process. It is sent
through the sensitive WhatsApp account and is not fed back to the model.

## 3. Capability schema

### Current contract limitation

The WIP's `PrivateReadProposal.from_model_args()` accepts exactly
`{capability_id}`. `PrivateReadCapabilitySpec` contains only
`capability_id`, `operation`, `resource_type`, and `fields`.
`TrustedAuthorizationBinding.resource_id` comes from trusted event context, and
the current `parameter_fingerprint` hashes only the capability spec. Therefore
an ad-hoc Gmail query or message ID cannot cross the current authorization
boundary safely. The adapter must never read a query from ambient model/event
state or infer one after authorization.

### Staged choice: fixed host-configured queries

Version 1 keeps the model surface exactly `{capability_id}`. The closed Gmail
configuration contains one or more reviewed fixed-query descriptors, but the
initial deployment enables one. At parse time, the gateway derives a generic
`ConfiguredPrivateReadOperation`:

```text
capability_id         = gmail.latest_message.read
operation             = private.latest_message.read
resource_type         = private_account_query
resource_id           = private-resource:<keyed account+query digest>
fields                = (sender, recipients, subject, date, text_body)
parameter_fingerprint = HMAC-SHA256(canonical operation descriptor)
approval_label        = reviewed non-private display text
adapter_key           = code-owned registry key, not durable authority
```

The generic capability spec gains trusted `resource_id`,
`parameter_fingerprint`, and `approval_label` values. The durable binding
already has fields for the first two, so the store schema need not hold query
plaintext. `PrivateReadAuthorizationOrchestrator` copies those exact trusted
values after capability resolution instead of using an event-global resource
or hashing an incomplete spec. Its request HMAC and binding digest therefore
cover them.

The canonical operation descriptor is closed JSON over provider kind, account
identity HMAC, exact operation version, query HMAC, fields, and all read caps.
Neither the account identity nor query is stored in the task, audit, OpenFGA,
or approval record. On restart, the host cancels/reconciles any non-terminal
task whose descriptor no longer matches the sealed current registry. Reusing a
capability ID with changed query bytes cannot revive an old approval.

The approval notification shows the fixed `approval_label`, operation, exact
field names, one-result/no-spam/no-trash rule, task generation, expiry, and a
short display fingerprint. The exact query was reviewed at configuration
deployment; it is not sent over ordinary WhatsApp. An approval is one-shot and
task-bound, not a standing mailbox grant.

### Deferred alternative: model-proposed parameters

A future `gmail.message.read` or ad-hoc-query feature would require a generic
bounded proposal-parameter envelope, canonical bytes, keyed durable
fingerprint, approval rendering, schema migration, resource mapping, replay
tests, and privacy scans. It must be provider-neutral in central authorization.
That larger change is explicitly deferred.

Accordingly:

- `gmail.latest_message.read` is the only v1 model-visible capability and maps
  to one fixed query.
- `gmail.message.read` is not model-visible in v1. The exact message ID returned
  by `messages.list` is an internal, same-invocation input to `messages.get`, not
  a second capability or ambient parameter.
- No configuration entry may turn an empty query, arbitrary query, or arbitrary
  message ID into a capability without a new reviewed descriptor.

### Generic composition proof

Central authorization resolves typed operations through a bounded
`PrivateReadOperationRegistry`; it does not branch on `gmail`, operation
keywords, resource-type substrings, or adapter class names. Tests register two
unrelated synthetic fixtures—for example a document-field adapter and a
sensor-snapshot adapter—with different resource/field shapes. They must pass
the same proposal, binding, approval, PDP, execution, and cleanup path. Gmail
is merely the first production adapter admitted by the closed composition.

## Engineering appendix

## 4. Concrete service composition

`compose_trusted_private_read_services()` will construct one exact
`GatewayPrivateReadComposition`; configuration cannot supply an import path,
callable, provider factory, command, module, URL, or executable.

The `TrustedPrivateReadHostServices` callables map exactly as follows:

- `healthy` → `GatewayPrivateReadComposition.healthy`
- `context_for_current_event` → `GatewayPrivateReadEventAuthority.current`
- `pdp_check` → `LocalOpenFgaPrivateReadPdp.check`
- `transport_registration` →
  `SensitiveWhatsAppRegistrationAuthority.registration_for`
- `private_read` → `PrivateReadOperationRegistry.execute`
- `deliver_notification` → `OrdinaryWhatsAppApprovalAuthority.notify`
- `decision_for_event` →
  `OrdinaryWhatsAppApprovalAuthority.decision_for_event`
- `close` → `GatewayPrivateReadComposition.aclose`
- `transport_identity` →
  `SensitiveWhatsAppRegistrationAuthority.anchored_transport_identity`
- `account_state` →
  `SensitiveWhatsAppRegistrationAuthority.anchored_account_state`
- `bind_event` → `GatewayPrivateReadEventAuthority.bind`
- `unbind_event` → `GatewayPrivateReadEventAuthority.unbind`

`transport_identity` and `account_state` return host-constructed, independently
anchored observations. They do not forward a service's self-description.
Self-reported bridge identity remains receipt evidence only.

### Closed configuration schema

The future schema is versioned and rejects unknown, missing, duplicate, or
wrongly typed keys. Placeholders below denote deployment values; this ADR does
not contain a real path, account identifier, credential, store identifier, or
session identifier.

```yaml
trusted_private_read:
  version: 2
  enabled: false
  state_dir: <canonical absolute owner-only directory>
  key_file: <canonical absolute owner-only 0600 regular file>
  transport_allowlist_file: <canonical absolute owner-only 0600 regular file>
  composition_seal_file: <canonical absolute owner-only 0600 regular file>

  gmail:
    kind: gmail_v1
    oauth_client_file: <canonical absolute owner-only 0600 regular file>
    oauth_token_file: <canonical absolute owner-only 0600 regular file>
    expected_profile_email: <exact provider-canonical Gmail identity>
    required_scopes:
      - https://www.googleapis.com/auth/gmail.readonly
    capabilities:
      - capability_id: gmail.latest_message.read
        approval_label: <reviewed non-private label>
        query: <reviewed fixed Gmail query>

  openfga:
    version: 1.18.2
    store_id: <reviewed local store identity>
    authorization_model_id: <reviewed model identity>
    policy_version: <reviewed policy version>
    policy_sha256: <reviewed lowercase SHA-256>

  approval:
    platform: whatsapp
    profile: <exact ordinary gateway profile>
    account: <exact ordinary provider account>
    owner_user: <exact authenticated owner>
    chat: <exact owner chat>
    thread: <exact thread sentinel>

  sensitive_delivery:
    platform: whatsapp
    profile: <exact sensitive profile>
    account: <exact sensitive provider account>
    destination_chat: <exact sensitive destination>
    destination_thread: <exact thread sentinel>
    ordinary_session_dir: <canonical absolute ordinary session directory>
    sensitive_session_dir: <canonical absolute sensitive session directory>
    launcher_path: <code-required canonical launcher path>
    runtime_root: <code-required canonical bridge root>
    node_binary: <canonical absolute reviewed Node executable>
    node_version: <exact reviewed version at or above 22.22.0>
    node_sha256: <reviewed lowercase SHA-256>

  limits:
    poll_seconds: 1.0
    lease_seconds: 30.0
    approval_ttl_seconds: 300
    connect_seconds: 2.0
    read_seconds: 5.0
    request_total_seconds: 8.0
    private_read_total_seconds: 20.0
    gmail_query_bytes: 512
    gmail_profile_or_list_bytes: 65536
    gmail_message_bytes: 262144
    mime_depth: 8
    mime_parts: 32
    decoded_candidate_bytes: 16384
    text_body_bytes: 3072
    rendered_plaintext_bytes: 4096
```

The parser accepts only narrower numeric limits than the code maxima. Paths
must be absolute, canonical, non-symlinked, owner/root-owned as appropriate,
non-group/world-writable through every ancestor, and have exact type, mode,
link count, device/inode, size, and content seals. Parsing never creates a
directory.

The Gmail API authority is fixed in code to
`https://gmail.googleapis.com`; the OAuth token authority is fixed to
`https://oauth2.googleapis.com`. Neither appears in configuration. OpenFGA is
fixed to `http://127.0.0.1:8080`, with code-owned paths beneath the configured
store ID. Remote authorities, DNS names, Unix-socket substitutions, proxies,
and TLS downgrades are rejected.

The key file retains separate versioned HMAC keys for audit, request,
request-ID, authorization, and receipts. The composition seal additionally
binds the closed config bytes, Gmail operation descriptors, OpenFGA identities,
Node binary, sensitive runtime tree, and all expected account roles. A value
may be rotated only by creating a new reviewed seal and terminalizing or
reconciling old work.

## 5. Gmail adapter

### Runtime choice

`GmailReadonlyPrivateReadAdapter` will use direct async REST calls through the
repository-pinned `httpx` runtime. It will not use `gws`, the Google Workspace
skill wrapper, a browser session, a global Google SDK discovery client, or a
globally authenticated CLI. Those surfaces can select a different account and
can expose query or response content through argv, stdout, task results, or
ambient credential resolution.

Direct REST keeps the permitted hosts, paths, headers, redirects, byte reads,
and JSON parser under the gateway's code-owned policy. OAuth refresh is also a
direct bounded POST to the fixed Google token endpoint. No provider URL is read
from credential JSON.

### Credential and account rules

The OAuth client and token are new dedicated files. Each is opened with
`O_NOFOLLOW`, checked as one-link owner-only `0600` regular data, read through
the verified descriptor, capped at 32 KiB, parsed as duplicate-free closed
JSON, and rechecked against its path seal. Parent directories satisfy the same
ancestor policy as the authorization store.

The client file contains only the reviewed installed-client identity material.
The token file contains only the matching client identity, refresh token,
exact granted scope list, and provisioning metadata required by the parser.
The exact scope set—not merely a superset—must equal:

```text
https://www.googleapis.com/auth/gmail.readonly
```

The broad existing personal Workspace token is neither read nor referenced.
No credential lookup falls back to a profile, home directory convention,
environment variable, keychain default, browser, ADC, or CLI cache.

At startup, after local verification, the adapter mints an in-memory access
token and calls `users.getProfile('me')`. It compares the exact returned
`emailAddress` with the configured provider-canonical identity using a
constant-time byte comparison after strict UTF-8/type checks. It discards
mailbox totals and `historyId` without persisting them.

Immediately before every private read, under the adapter's single-operation
lock and after ensuring the access token will outlive the outer deadline, it
calls `getProfile('me')` again and repeats the exact comparison. Only then may
it issue list and get. A profile mismatch, token/client mismatch, scope
mismatch, account drift, or inability to revalidate closes the adapter and
revokes host health.

### Token refresh

The refresh token is never changed by normal operation. The adapter posts the
fixed OAuth refresh grant over HTTPS with redirects disabled and credentials in
the request body—not argv, env, URLs, or logs. It accepts only a bounded closed
response containing a bearer access token, positive bounded expiry, and an
exact scope value when Google returns one. Unknown token type, expanded scope,
malformed or omitted required fields, provider error, or excessive expiry
fails closed with a content-free local error.

Access tokens live only in a wipeable in-memory holder, are replaced before
expiry, and are cleared on close. They are not written back to the token file.
Creating or revoking the dedicated refresh token remains a later explicit OAuth
authorization boundary.

### Exact Gmail sequence

For `gmail.latest_message.read`, the adapter performs:

1. fresh `GET /gmail/v1/users/me/profile` and exact account comparison;
2. `GET /gmail/v1/users/me/messages` with exactly `q=<fixed query>`,
   `maxResults=1`, and `includeSpamTrash=false`, with no `pageToken` or label
   parameter;
3. validation that zero results means a content-free no-match failure and one
   result contains only bounded `id` and `threadId` values; and
4. `GET /gmail/v1/users/me/messages/{exact-id}` with exactly `format=full`.

List and get are deliberately separate because the Gmail list contract returns
only IDs. The adapter never follows `nextPageToken`. If Gmail returns more than
one entry despite the request, it fails.

### Closed parsing and DTO

The JSON loader uses an object-pairs hook that rejects duplicates before a
dictionary exists, then a depth/entry/type walker. Each Gmail object has an
explicit required/optional key set. Documented but forbidden values such as
labels, snippet, history, size estimates, and mailbox totals may be type-checked
and immediately discarded; unknown keys fail closed so provider expansion is a
review event.

The MIME walker is iterative and enforces the depth, part, header, encoded, and
decoded budgets before allocation. It does not invoke a general HTML renderer
or MIME attachment loader. It:

- treats a non-empty filename or `Content-Disposition: attachment` as an
  attachment and never decodes its body;
- does not fetch `attachmentId`;
- ignores `text/html` and other non-plain leaves;
- does not traverse `message/rfc822`;
- accepts exactly one non-attachment `text/plain` leaf with inline `body.data`;
- strictly base64url-decodes into a bounded wipeable buffer;
- requires declared UTF-8 or ASCII-compatible plain text and converts to strict
  UTF-8 without replacement characters; and
- normalizes line endings only, rejecting dangerous controls and overlong text.

The parser emits an exact frozen `GmailMessageReadDto` with five header fields
and `text_body`. Header decoding uses a closed RFC header parser, rejects
duplicate allowlisted headers and folding/newline injection, and never includes
unlisted headers. Missing allowlisted headers render as a fixed `(not present)`
marker; malformed values fail.

`render_gmail_message_read()` is pure and deterministic: fixed field order,
fixed ASCII labels, LF separators, no Markdown/HTML/linkification, no locale,
no model, and a final 4,096-byte assertion. It omits message/thread IDs in v1.

### Failure hygiene

Provider response bodies are accumulated only in bounded mutable buffers and
wiped in `finally`. The adapter never interpolates URLs, IDs, queries, headers,
provider bodies, credential fields, or upstream exceptions into an exception.
It catches provider/parser failures inside the frame that owns private locals,
clears response references and buffers, exits that handler, and only then raises
a new content-free `PrivateReadProviderFailure` with `from None`.

The host directly awaits the adapter; it does not wrap private output in a
background task whose completed result is retained. The typed DTO and rendered
string are cleared after the sensitive bridge consumes them. Cancellation and
every `BaseException` run the same cleanup. No private response is cached or
persisted.

## 6. OpenFGA adapter

`LocalOpenFgaPrivateReadPdp` is a code-owned direct HTTP adapter for exactly
OpenFGA 1.18.2 at the fixed loopback endpoint. Configuration supplies only the
reviewed local store ID, authorization model ID, policy version, and policy
hash. Startup verifies the running version and exact model identity/hash without
creating a store, model, tuple, or service.

For every field in the immutable sorted `TrustedAuthorizationBinding.fields`,
the adapter sends one independent `POST /stores/{store_id}/check` at both
`pre_claim` and `pre_private_read`. It does not batch fields. Each request has:

- the exact configured `authorization_model_id`;
- a user derived from the bound requester/worker principal through a keyed,
  versioned identifier mapping;
- the relation derived through the generic configured field relation map;
- object `private_resource:<resource_id digest>`;
- no private query, account identity, Gmail ID, header, or body; and
- `consistency: HIGHER_CONSISTENCY`.

No positive or negative decision cache exists in the gateway. Every field must
return one non-redirect 200 response whose duplicate-free closed JSON is exactly
`{"allowed": <boolean>}`. The response cap is 4 KiB. Unknown keys, non-boolean
values, partial reads, timeout, cancellation, connection error, non-200,
redirect, malformed JSON, or oversize response returns aggregate `failure`.
Any explicit false returns aggregate `deny`; only all true values return
`allow`.

The adapter copies the exact host-minted `context_id` and `pdp_call_id` from the
input into `ExternalPdpDecisionResult`. Individual outbound field calls use
bounded child IDs derived from the root call ID and field ordinal for local
diagnostics, but OpenFGA is not claimed to echo or attest them. The durable
store factory revalidates the root IDs, coordinator fence, task version,
binding, claim, model, policy, and stage as it already does.

`consistency='strongest'` and `cache_used=False` mean only that this local
adapter sent `HIGHER_CONSISTENCY` on every request and used no application
cache. They do not assert linearizability or a server-issued consistency token.

Starting OpenFGA, creating its store/model, and writing policy tuples occur only
at later explicit deployment boundaries. This implementation task must use a
fake local endpoint and must not contact or mutate a live OpenFGA service.

## 7. Approval notification and authenticated decision

`OrdinaryWhatsAppApprovalAuthority` is gateway-owned and is constructed around
the already connected, local ordinary WhatsApp adapter selected by exact
profile/account identity. It cannot resolve a relay adapter or use a generic
`send_message` tool.

The approval notification contains no Gmail plaintext, query, account identity,
message ID, sender, recipient, subject, date, or body. It contains only:

- the reviewed capability label and fixed field list;
- “one result, no spam/trash, plain text only”;
- the task display token, challenge generation, expiry, and approve/deny
  instructions; and
- a challenge-bound interaction/reply target.

Notification send evidence is honest. A successful ordinary adapter submission
with an exact provider message ID produces `ProviderAcceptanceEvidence` with
`status='provider_accepted'`, the adapter instance/account/connection binding,
and destination binding. This means the provider accepted the submission. It
is not called delivered, received, displayed, or read.

An owner decision is accepted only from a native authenticated ordinary
WhatsApp event whose gateway profile, live adapter instance, account binding,
connection epoch, chat, thread, sender, source message, quoted provider message
ID, task, challenge attempt, generation, and regenerated nonce all match the
accepted challenge and durable binding. The event must have
`authenticated_reply` provenance. Provider body text and display names are not
identity.

A copied, pasted, quoted-as-text, forwarded, replayed, cross-chat, cross-account,
cross-profile, stale-generation, or unthreaded approval string has no authority.
The existing ordinary bridge's native quoted-message metadata must be carried
through a new exact typed approval observation; quoted text itself is neither
necessary nor trusted.

If the ordinary transport is unavailable before submission, no acceptance
evidence is minted. A bounded definitive pre-submit failure may schedule a new
notification attempt under the store's retry cap. An ambiguous post-submit
outcome consumes that attempt and requires a new challenge generation; it is
never replayed as the same message. Without a provider-accepted challenge and
matching authenticated decision, the task remains unapproved and expires. No
Gmail read occurs.

## 8. Sensitive registration and executable binding

The WIP gap is closed by making
`SensitiveWhatsAppRegistrationAuthority` the sole creator of the registration.
No service may supply a command, executable, digest, verifier, or identity.

### Independent artifact authority

Before any service, store, session, or subprocess access, the config parser
opens the actual code-required `launcher.js` with `O_NOFOLLOW`, validates every
ancestor, file type, owner, mode, link count, device/inode, size, timestamps,
and reviewed digest, and keeps an owned descriptor/seal. It independently
anchors:

- launcher bytes;
- `transport-manifest.json` bytes and manifest version;
- verifier bytes;
- all executable source bytes;
- package and lock bytes;
- the complete installed `node_modules` tree identity;
- the reviewed Baileys rc14 package identity; and
- the pinned Node binary's path, inode, bytes, version, and digest.

Bridge self-reporting is checked against those values but remains receipt-only.
The source of authority is the host's reviewed allowlist and open-descriptor
observation.

### The registration executes what was verified

`SensitiveDeliveryTransportRegistration` gains an exact host-owned
`SensitiveLaunchBundleBinding`. The registration command cannot name an
executable or script independently. Immediately before spawn, the router:

1. rechecks the original launcher, runtime root, manifest, dependency tree, and
   Node seals;
2. copies the complete manifest-bound launch bundle from verified descriptors
   into a new owner-only private staging directory, rejecting symlinks,
   hardlinks, replacements, unknown files, and aggregate-size overflow;
3. re-hashes every staged file and compares its manifest and original
   device/inode/byte binding;
4. stages the pinned Node executable from its verified descriptor;
5. constructs fixed arguments internally so staged Node executes only the
   staged `launcher.js`; and
6. rechecks the staged paths and descriptors at the final pre-`execve` boundary.

Thus the exact launcher bytes verified by config are the launcher bytes staged
and interpreted. No unrelated service-supplied executable or digest can enter
the registration. Failed staging removes the entire private tree; uncertain
cleanup revokes host health.

Tests replace the launcher path, swap ancestors, introduce a symlink, add a
hardlink, mutate after open, mutate during copy, swap the Node binary, and race
the final spawn. Every case must fail before a private body is read or written.

### Account and process separation

The ordinary and sensitive accounts, profiles, session directories, processes,
sockets, locks, dependency graphs, queues, indexes, loggers, hooks, and retry
paths remain separate as required by
[`scripts/whatsapp-sensitive-bridge`](../../scripts/whatsapp-sensitive-bridge/README.md).
Their canonical account identities must be distinct and in the same proved
provider namespace. The ordinary session is inspected only for filesystem
identity/separation, never for credential contents.

Stored sensitive account mismatch, equality with the ordinary account,
namespace ambiguity, missing LID readiness, session seal drift, or live socket
identity drift terminates the sensitive attempt before socket creation or
before stdin is opened. Pairing is absent from production startup.

The result is framed on bounded stdin after the one-shot send authority is
consumed. One exact provider send is attempted. A timeout, cancellation,
connection loss, or other ambiguous post-submit outcome burns authorization;
there is no retry. Provider acknowledgement evidence retains the existing
receipt semantics and is not upgraded by this ADR.

## 9. Startup and shutdown ordering

Startup is one transaction in this strict order:

1. Revoke any prior process-global private-read runtime/tool and clear any old
   event context.
2. Parse the closed versioned configuration without creating paths, starting
   processes, loading sessions, opening SQLite, or contacting a service.
3. Verify the sensitive launcher first; then verify every config/key/allowlist/
   credential/session/runtime path and seal, dedicated OAuth scope declaration,
   expected identities, Node binary bytes/version, and composition seal. No
   private read occurs. Launcher verification precedes any service, store,
   session, or process access.
4. Construct the exact composition, operation registry, event authority, HTTP
   clients, and sensitive registration authority in an inert unpublished
   state. Constructors perform no network, session, store, or subprocess work.
5. Run process/session/plaintext-inert checks: local OpenFGA reachability and
   exact version/model/policy identity, Gmail token refresh and `getProfile`
   identity only, ordinary live adapter identity, and local sensitive
   filesystem/account readiness. Do not open a sensitive socket or read a
   Gmail message.
6. Recheck all seals, then open/reconcile the authorization store, acquire the
   singleton coordinator, and create the worker. Reconciliation cancels work
   whose operation descriptor or identity set no longer matches.
7. Recheck health and seals, then atomically publish the host pointer, runtime,
   and tool as one generation. There is never a tool-visible partially
   initialized interval.

Any failure unwinds completed steps in reverse and leaves the host pointer and
tool unavailable. Cleanup closes and awaits HTTP clients, response streams,
workers, coordinator locks, SQLite connections, subprocesses, process groups,
sockets, pipes, descriptors, staged directories, token holders, and task-local
context.

Every `BaseException`, including cancellation, `KeyboardInterrupt`,
`SystemExit`, worker failure, and gateway shutdown, follows the same revocation
and cleanup path. Cleanup failure keeps the tool revoked and emits only a
content-free fixed diagnostic. Shutdown first unpublishes the runtime/tool,
then cancels work, then closes resources in reverse construction order.

## 10. Relay compatibility

The rejected WIP's Discord component path trusts an optional
`authenticatedUserId` envelope field, but this repository contains no verified
external connector producer. Documentation is not deployment evidence.

The relay contract must add an explicit versioned capability,
`passthrough.authenticated_user_id.v1`, negotiated in the authenticated hello
exchange and bound to an allowlisted connector implementation/version. The
gateway must:

- reject the capability if the connector contract version is unknown;
- reject an `authenticatedUserId` field unless the capability was negotiated;
- reject Discord prompt-component resolution if the capability is absent;
- require the field to be a non-empty bounded provider-authenticated envelope
  value and combine it with the immutable prompt-source snapshot;
- never fall back to provider-body user/channel/profile fields; and
- renegotiate or disable component handling after reconnect/version drift.

An older connector may continue unrelated relay functions, but component
approval handling fails closed; it cannot silently downgrade to text ownership.
Connector-side producer tests and deployment evidence are required separately
before claiming compatibility.

Juno's v1 approval path is native local ordinary WhatsApp and does not use the
relay, Discord, or `authenticatedUserId`. Relay availability therefore cannot
enable, disable, or nominate authority for Juno's private read.

## 11. Dataflow and privacy proof

The only permitted plaintext flow is:

1. Google TLS records terminate in the dedicated `httpx` client.
2. Bounded mutable response bytes enter the duplicate-rejecting closed JSON
   parser.
3. The MIME walker produces one bounded immutable `GmailMessageReadDto`; raw
   buffers are wiped.
4. The pure renderer produces one at-most-4,096-byte plaintext string in the
   parent private-read worker's memory.
5. The parent rechecks host, PDP, launcher, account, and one-shot send authority.
6. The sensitive router writes a fixed metadata header and the plaintext over
   its inherited bounded pipe to the separately staged sensitive bridge.
7. The sensitive bridge performs one send through its separate WhatsApp
   provider socket and clears its buffers.
8. The parent clears DTO/string references and closes/wipes the pipe and staged
   process state regardless of outcome.

Plaintext does **not** flow through the model API, conversation message list,
tool result, ordinary gateway send router, ordinary WhatsApp process, relay,
OpenFGA request, task/audit row, SQLite journal/WAL, session database, memory,
trajectory, trace, metric, log formatter, exception, command line, environment,
filesystem, cache, search index, replay record, or notification.

Durable state may contain only bounded non-plaintext authorization metadata:
task/correlation IDs, generation, expiry, HMAC-derived requester/resource/query
tokens, parameter/binding/request digests, configured operation and field names,
policy/model identifiers, claim/coordinator fences, provider message verifiers,
and content-free receipt status. Approval and delivery provider message IDs are
stored only where the existing contracts require replay/correlation evidence.
The Gmail message/thread IDs and private header/body values are ephemeral and
not durable.

The privacy proof is enforced by sentinel scans, not by relying on a reviewer to
notice a log call. Tests insert distinct sentinels into every provider field,
credential-like field, query, message ID, header, and body and scan all
forbidden surfaces after success, every failure point, cancellation, restart,
and cleanup.

## 12. TDD implementation plan

Every behavior starts with a failing test committed before or with the smallest
production change that makes it green. Mocks may test local edges, but the
resolution, path, HTTP, store, process, and privacy boundaries require real
imports and temporary owner-only state.

### Slice 1: dead composition to exact composition

**RED:** add `tests/gateway/test_private_read_composition.py` proving default
and incomplete config remain unavailable, while one complete closed config
constructs all twelve exact service callables and no arbitrary factory/import/
command key is accepted. Add two unrelated synthetic adapters/resources to
prove generic central dispatch.

**GREEN:** add the inert composition, generic configured-operation descriptor,
registry, and exact callable wiring. Do not contact providers.

```sh
python -m pytest tests/gateway/test_private_read_composition.py \
  tests/gateway/test_private_read_authorization.py -q
```

### Slice 2: durable fixed-parameter binding

**RED:** extend `tests/gateway/test_private_read_authorization.py` and add
`tests/gateway/test_private_read_capability_binding.py` for trusted
`resource_id`, keyed `parameter_fingerprint`, approval label, query-change
reconciliation, replay, capability-ID reuse, no plaintext query in SQLite, and
the explicit rejection of model `query` or `message_id` arguments.

**GREEN:** extend the generic spec/orchestrator without adding Gmail branching
or a new durable plaintext column.

```sh
python -m pytest tests/gateway/test_private_read_authorization.py \
  tests/gateway/test_private_read_capability_binding.py \
  tests/gateway/test_authorization_tasks.py -q
```

### Slice 3: credential and profile boundary

**RED:** add `tests/gateway/test_gmail_private_read_credentials.py` for exact
scope, extra/missing scope, client mismatch, expected-profile mismatch,
symlink/hardlink/mode/owner/ancestor/path replacement, duplicate JSON keys,
oversize files, ambient credential isolation, and no token persistence. Test
startup profile verification and a second fresh verification immediately before
read, including an account-race fixture between startup and operation.

**GREEN:** implement owner-only credential loading, direct refresh, fixed hosts,
token holder, and profile verifier.

```sh
python -m pytest tests/gateway/test_gmail_private_read_credentials.py -q
```

### Slice 4: bounded Gmail HTTP and MIME

**RED:** add `tests/gateway/test_gmail_private_read_adapter.py` and
`tests/gateway/test_gmail_private_read_mime.py`. Cover fixed authority/path,
TLS, no redirects/proxy/env trust, timeouts, streamed caps, duplicate/malformed
JSON, list `maxResults=1`, `includeSpamTrash=false`, exact fixed `q`, separate
get with `format=full`, no pagination, zero/multiple/list-get mismatch, strict
headers, base64url, attachment/HTML ignore, no safe plain part, multiple plain
parts, depth/part/header/encoded/decoded/body/render caps, control injection,
and deterministic output.

Use a real local fake HTTPS server with a test CA and an injectable exact
transport that still validates method, authority, path, query, headers,
streaming, and redirect behavior. Never use live Gmail.

**GREEN:** implement the adapter, closed parser, DTO, renderer, and cleanup.

```sh
python -m pytest tests/gateway/test_gmail_private_read_adapter.py \
  tests/gateway/test_gmail_private_read_mime.py -q
```

### Slice 5: OpenFGA two-phase, per-field checks

**RED:** add `tests/gateway/test_openfga_private_read_adapter.py` against a real
local fake HTTP server. Assert one request per exact field at `pre_claim` and
again at `pre_private_read`, fixed loopback authority/store/model, generic
resource/relation mapping, `HIGHER_CONSISTENCY` on every call, no cache, exact
root IDs in local evidence, and deny/failure behavior for false, timeout,
cancellation, redirect, non-200, duplicate/unknown keys, malformed/oversized
body, or identity drift.

**GREEN:** implement the pinned 1.18.2 adapter and aggregate result.

```sh
python -m pytest tests/gateway/test_openfga_private_read_adapter.py \
  tests/gateway/test_authorization_pdp_evidence.py -q
```

### Slice 6: notification and decision provenance

**RED:** add `tests/gateway/test_private_read_whatsapp_approval.py` for exact
ordinary adapter/profile/account/chat/sender binding, provider-acceptance
semantics, no read/delivery claim, unavailable transport, definitive failure,
ambiguous submission, challenge regeneration, replay, copied/quoted/forwarded
text, wrong principal/account/chat/task/generation/reply target, connection
epoch drift, expiry, and native quoted-message provenance.

**GREEN:** implement the gateway-owned approval authority and typed native
WhatsApp observation. No private value enters a notification.

```sh
python -m pytest tests/gateway/test_private_read_whatsapp_approval.py \
  tests/gateway/test_authorization_notifications.py -q
```

### Slice 7: exact sensitive executable binding

**RED:** add `tests/gateway/test_private_read_sensitive_registration.py` and
extend `tests/gateway/test_sensitive_delivery.py` for the exact
verified-to-staged-to-executed launcher, full manifest/verifier/source/module
identity, independent Node pin, service-supplied command rejection, pre-spawn
recheck, symlink/hardlink/path/ancestor replacement, inode/byte mutation at each
TOCTOU point, account/session/process/socket separation, mismatch before socket,
and no retry after ambiguous submit.

Extend the existing Node tests under
`scripts/whatsapp-sensitive-bridge/*.test.mjs` for the staged-bundle contract,
rc14 identity, lifecycle, provisioning separation, and alphanumeric-code-only
pairing. QR remains absent.

**GREEN:** add the host-owned launch-bundle binding and registration authority;
make the router stage and execute only that binding.

```sh
python -m pytest tests/gateway/test_private_read_sensitive_registration.py \
  tests/gateway/test_sensitive_delivery.py -q
node --test --test-concurrency=1 \
  scripts/whatsapp-sensitive-bridge/*.test.mjs
```

### Slice 8: startup transaction and privacy proof

**RED:** add `tests/gateway/test_private_read_startup_transaction.py` and
`tests/gateway/test_private_read_privacy.py`. Inject ordinary exceptions,
`BaseException`, cancellation, and shutdown at every startup, publish, read,
delivery, and reverse-cleanup checkpoint. Assert atomic unavailability and
closure of clients, workers, processes, sockets, descriptors, stores, contexts,
and staged trees.

Scan sentinels in captured logs, exception strings/chains, traceback locals,
completed asyncio task results, authorization DB/WAL/journal, policy request
bodies, audit rows, temp/state files, command args, environment, model messages,
session history, memory, caches, and indexes.

**GREEN:** reorder startup and unify revocation/cleanup.

```sh
python -m pytest tests/gateway/test_private_read_startup_transaction.py \
  tests/gateway/test_private_read_privacy.py \
  tests/gateway/test_trusted_private_read_host.py -q
```

### Slice 9: relay negotiation, typing, and docs

**RED:** extend
`tests/gateway/relay/test_relay_passthrough.py`,
`tests/gateway/relay/test_ws_transport.py`, and
`tests/gateway/relay/test_ws_callback_dispatch.py` for capability negotiation,
unknown/old connector behavior, unnegotiated/spoofed/missing
`authenticatedUserId`, reconnect drift, and proof that local WhatsApp is
independent.

**GREEN:** add the versioned relay capability and fail-closed component gate.
Update the English dependency docs that currently say Node 20+, v22, or 26+
where they describe the root Hermes runtime—at minimum `CONTRIBUTING.md`,
`website/docs/developer-guide/contributing.md`,
`website/docs/getting-started/installation.md`,
`website/docs/user-guide/messaging/whatsapp.md`, and
`website/docs/user-guide/windows-native.md`—to agree with root
`package.json`: Node `>=22.22.0`. Product-specific skills with independent
engine constraints are not mechanically rewritten.

Run changed-file `ty` from the exact WIP base. The known candidate baseline is
26 diagnostics; implementation is not acceptable until every candidate-only
diagnostic is fixed rather than excluded or baseline-suppressed.

```sh
python -m pytest tests/gateway/relay/test_relay_passthrough.py \
  tests/gateway/relay/test_ws_transport.py \
  tests/gateway/relay/test_ws_callback_dispatch.py -q
git diff --name-only -z 49d78bdc915e9e2c3ff78d7d4a3a7074ddb6ac85 \
  -- '*.py' | xargs -0 .venv/bin/ty check
```

### Slice 10: required regression evidence

Run the full focused authorization, relay, terminal, lifecycle, privacy, and
rc14 suites, including all existing modules named in this ADR. Then run the
repository test script in the supported environment. No test may use a real
account, credential, session, Gmail endpoint, OpenFGA deployment, or WhatsApp
send.

```sh
python -m pytest tests/gateway/test_private_read_authorization.py \
  tests/gateway/test_trusted_private_read_host.py \
  tests/gateway/test_sensitive_delivery.py \
  tests/gateway/test_active_principal_lifecycle.py \
  tests/gateway/relay -q
node --test --test-concurrency=1 \
  scripts/whatsapp-sensitive-bridge/*.test.mjs
scripts/run_tests.sh
git diff --check
```

All test account/resource values are unrelated synthetic fixtures. No real
account/session identifier or copied token/mailbox value is permitted in a
fixture, snapshot, failure output, or artifact.

## 13. Deployment approval boundaries

These are separate decisions in order. Approval of one does not imply any
later step:

1. Land the reviewed implementation commit.
2. Install/deploy the candidate with the private-read feature still off.
3. Create a dedicated Gmail OAuth client/token and grant exactly
   `gmail.readonly`.
4. Start/provision pinned OpenFGA 1.18.2, its reviewed store/model, and policy.
5. Provision and pair the separate sensitive WhatsApp account using an
   alphanumeric code—never QR.
6. Connect and verify the ordinary and sensitive transports independently.
7. Send one exact approved non-private canary through the isolated sensitive
   transport.
8. Approve and execute the first private Gmail read.

Rollback or failure at any stage leaves all later stages unauthorized. A canary
does not authorize Gmail. OAuth consent does not authorize a read. Pairing does
not authorize a canary or result. OpenFGA provisioning does not authorize
transport connection.

## 14. Alternatives and non-goals

Rejected alternatives:

- **Reuse the broad personal Workspace token.** It violates least privilege,
  identity isolation, and the explicit authorization boundary.
- **Run `gws`, a skill, or a Google CLI subprocess.** Ambient account selection
  and argv/stdout/task-result surfaces are outside the private-read proof.
- **Use IMAP or an App Password.** It creates a second protocol/credential
  surface, weaker operation typing, and no advantage over the selected Gmail
  REST contract.
- **Request Gmail modify/send or broader scopes.** V1 is read-only. Provider
  credential scope must be exactly `gmail.readonly` even though that scope can
  view settings; the adapter never calls settings APIs.
- **Ask the model to summarize or redact the body.** That places private text in
  model context and makes exposure probabilistic.
- **Configure a provider factory, import path, command, executable, or URL.**
  Those are authority injection points, not reviewed data selection.
- **Deliver the result over ordinary WhatsApp.** The approval account/process
  is not a private result destination.
- **Support HTML or attachments in v1.** Rendering, remote loads, MIME
  ambiguity, and payload size expand the threat surface materially.
- **Select among multiple accounts in v1.** One exact live Gmail profile is a
  startup and per-read invariant.
- **Expose `gmail.message.read` or ad-hoc `q` in v1.** The present proposal
  contract cannot bind model parameters. The generic migration is deferred.

Non-goals include Gmail search browsing, inbox summaries, threads, history,
settings, labels, contacts, background polling, webhook/watch integration,
mailbox indexing, result replay, and provider writes of any kind.

## 15. Acceptance checklist and implementation sequence

No item below is claimed complete by this ADR.

### Gated implementation commits

1. **Contracts:** add failing generic capability-binding/composition tests;
   implement fixed trusted descriptors and two synthetic adapters. Security
   review: no Gmail branching or query plaintext in durable state.
2. **Gmail boundary:** add failing credential/profile/HTTP/MIME/privacy tests;
   implement the direct bounded adapter. Security review: exact scope/account,
   fixed hosts, parser bounds, and exception hygiene.
3. **Policy boundary:** add failing OpenFGA per-field/two-stage tests; implement
   the pinned loopback adapter. Policy review: exact model/tuples and truthful
   consistency terminology.
4. **Approval boundary:** add failing ordinary WhatsApp provenance/replay tests;
   implement notification and decision authorities. Gateway review: native
   authenticated reply evidence only.
5. **Sensitive boundary:** add failing artifact/TOCTOU/account/process tests;
   implement launch-bundle binding and exact registration. Runtime review:
   independently anchored Node/manifest/source/modules and no retry ambiguity.
6. **Lifecycle and relay:** add failing transactional startup/privacy/relay
   negotiation tests; implement atomic publication, reverse unwind, and relay
   gating. Correct all 26 candidate-only `ty` diagnostics and Node
   `>=22.22.0` English docs.
7. **Regression/release evidence:** run focused and full suites, archive only
   content-free command/status evidence, and obtain product, security, policy,
   gateway, and release sign-off before merge.

### Release evidence required before deployment

- exact source commit/tree and reviewed diff;
- all focused RED-to-GREEN test history and final command exits;
- zero candidate-only `ty` diagnostics and clean `git diff --check`;
- fake-HTTPS and fake-OpenFGA contract evidence with no live calls;
- privacy sentinel scan evidence across every forbidden surface;
- launcher/manifest/source/dependency/Node identity review;
- relay connector producer/version evidence, or documented disabled component
  handling;
- separate records for each deployment approval boundary; and
- rollback evidence showing the runtime/tool is absent after every injected
  startup and cleanup failure.

### Unresolved deployment values, not design permissions

The implementation design is closed, but real deployment values do not exist
in this ADR: the dedicated OAuth client/token and expected Gmail profile, local
OpenFGA store/model/policy identities, ordinary and sensitive provider
identities/session paths, reviewed Node binary identity, and final composition
seal. Each must be created or selected at its own later authorization boundary.

The external relay connector's production of negotiated authenticated-user
metadata also remains unverified. Until separate connector evidence exists,
Discord component handling must remain unavailable. None of these unresolved
deployment values permits implementation code to fall back to ambient state.
