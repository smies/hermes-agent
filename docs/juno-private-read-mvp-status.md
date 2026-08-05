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
the separate sensitive WhatsApp process. Model and ordinary surfaces receive
only fixed status text. A successful transport result is called `submitted`;
it is not a delivery or read claim.

The implementation is deliberately smaller than the accepted high-assurance
ADR. The ADR is unchanged and remains the hardening roadmap. In particular,
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
- Pair and qualify the already-separate sensitive WhatsApp account/session,
  supply its loopback capability, and verify it differs from the ordinary
  account before connection. No auth state is read or mutated by this change.
- Create the owner-only Juno version-2 config and credential files, configure
  the dedicated `juno` profile/process, and run a supervised synthetic canary
  before any mailbox use.
- Complete operator review of logging, backup, crash-dump, task/session, and
  endpoint configuration on the deployment host.

No production profile, launch service, mailbox, OpenFGA instance, OAuth
credential, WhatsApp auth state, pairing flow, or external Juno system record
was changed while producing this candidate.
