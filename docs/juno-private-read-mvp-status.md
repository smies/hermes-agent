# Juno private-read MVP status (Option 2)

Status as of 2026-08-05: **offline implementation candidate; not authorized
or ready for deployment**.

This slice implements the selected fast middle ground for exactly
`gmail.newest_inbox_message.read`. It binds an authenticated inbound WhatsApp
profile/account/chat/sender to one allowlisted sensitive destination, uses the
existing authorization SQLite database for a short-lived one-shot request,
intercepts exact `/approve <id>` and `/deny <id>` commands before ordinary
gateway dispatch, performs one fresh OpenFGA check immediately before the
Gmail read, renders the fixed six-field plaintext form, and submits it through
the separate sensitive linked-device process. Juno keeps one public WhatsApp
account, number, and visible identity. The ordinary and sensitive processes
use independently paired credentials, auth roots, sockets, generations, and
runtime capabilities for that same canonical account. Model and ordinary surfaces receive
only fixed status text. A successful transport result is called `submitted`;
it is not a delivery or read claim.

Each durable request binds the complete reviewed sensitive artifact identity,
loopback authority, and exact `juno-sensitive-submit-v2` contract through its
provider-authority and descriptor digests. Submission carries the request's
microsecond deadline through the authenticated loopback body and rechecks it at
the Python coroutine, HTTP issue, Node handler, delivery-core, and provider-send
boundaries. Every private request is bound to the exact configured James 1:1
destination; groups and alternate users are rejected. Version-2 hosting is
unavailable in multiplexed gateway processes; it requires a dedicated
non-multiplexed Juno runner.

The plaintext-bearing receiver performs a final synchronous durable burn before
Baileys invocation. Its replay root and sibling anchor are independent of
authorization SQLite, survive receiver replacement, and store only bounded
request/descriptor digests. They are initialized only while the Juno state
directory is pristine; once any Juno state exists, missing, corrupt, aliased,
hardlinked, incorrectly owned/mode-set, or unwritable replay authority prevents
sensitive publication.
Tombstones are never expired or pruned, so logical request IDs never become
reusable; operational growth is permanent and must be monitored. The sensitive
child also holds authority only while the exact supervisor-owned stdin pipe is
live. Parent EOF/error closes the listener/provider socket and exits, while an
unknown listener on port 3011 remains a fail-closed startup error.

The enforceable guarantee is application containment: private Gmail plaintext
must not reach the low-trust model, prompt/tool/session history, ordinary
inbound queue, extractor, quote/sent index, mirrors, hooks, logs, standard
output/error, audit/PDP/authorization data, retry/dead-letter storage, or
ordinary delivery APIs. Only the dedicated `juno` profile's host-attested
ordinary runtime fences authenticated Baileys `key.fromMe` events, at the
first production `messages.upsert` callback before diagnostics or content
inspection. Baileys does not provide a trustworthy distinction between an
owner-typed own message and sender-companion fan-out, so the Juno private-read
ordinary session deliberately drops all `fromMe` events. Generic self-chat and
bot-mode `WHATSAPP_FORWARD_OWNER_MESSAGES` behavior remains unchanged when
the private-read fence is absent. This is not an account-level
plaintext boundary: sender-companion fan-out can expose plaintext to another
linked Juno device and shared WhatsApp history, and the ordinary bridge may
decrypt it in process memory before the callback fence. WhatsApp-account and
same-UID/process-memory compromise remain outside the boundary.

Fence authority is not an ambient boolean. The dedicated gateway generates a
per-adapter runtime key before launching the reviewed ordinary bridge. Bridge
health returns a profile/runtime/timestamp/artifact-bound HMAC proof; the
adapter verifies it against the anchored launcher, manifest, source and local
bridge bytes. Missing, false, malformed, stale, cross-profile, cross-adapter,
or runtime-drifted evidence removes the private-read tool surface. Evidence is
refreshed continuously, and version-2 hosting remains unavailable under
profile multiplexing.

The implementation is deliberately smaller than the accepted high-assurance
ADR. This product decision revises the ADR's WhatsApp topology and threat
boundary; the rest remains the hardening roadmap. In particular,
this MVP does not implement native polls, signed prepare/commit evidence,
destination ACK/READ/PLAYED proof, immutable publication generations, signed
OpenFGA policy manifests, policy epoch attestation, two-stage checks, custom
root supervision, new service UIDs, or same-UID isolation. Owner-only files
are hygiene only; code running as the same macOS UID remains in the TCB.

## Deployment gates still closed

- Create and review a dedicated Google OAuth client and token whose returned
  scope is exactly `https://www.googleapis.com/auth/gmail.readonly`, then bind
  the live Gmail profile response to the configured account.
- Provision the OpenFGA 1.18.2 store/model/tuples and local API credential;
  review the exact `HIGHER_CONSISTENCY` check body. No live store is created by
  this change.
- Pair and qualify a second linked-device session for the same canonical Juno
  account using pairing code only. Prove the two auth trees, credential sets,
  device identities, processes, sockets, and generations are distinct, and
  fail closed on unknown PN/LID topology or drift. No live auth state is read
  or mutated by this change.
- Create the owner-only Juno version-2 config and credential files, configure
  the dedicated `juno` profile/process, and run a supervised synthetic canary
  before any mailbox use.
- Complete operator review of logging, backup, crash-dump, task/session, and
  endpoint configuration on the deployment host.

No production profile, launch service, mailbox, OpenFGA instance, OAuth
credential, WhatsApp auth state, pairing flow, or external Juno system record
was changed while producing this candidate.
