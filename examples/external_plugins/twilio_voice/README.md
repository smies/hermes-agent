# Hermes Twilio inbound voice bridge

This is a standalone, inbound-only Hermes v0.20 platform plugin. Twilio
ConversationRelay owns PSTN audio, speech recognition, and speech synthesis;
the existing default-profile Hermes agent remains the model, memory, skill,
session, and tool runtime. It adds no model tool and requires no Hermes core
change.

The implementation has not been exercised against live PSTN traffic. The
repository tests use signed synthetic Twilio requests and a fake Hermes
adapter because this build was explicitly prohibited from changing live
Twilio, Cloudflare, launchd, credentials, or running services.

## Security model

The HTTP TwiML request and initial WebSocket upgrade are independently checked
with Twilio's HMAC-SHA1 request signature before a frame reaches Hermes. The
HTTP request creates a bounded, expiring, one-use nonce; the WebSocket `setup`
frame must bind that nonce to the same Account SID, Call SID, caller, called
number, and inbound direction. An E.164 caller allowlist is checked before the
agent is invoked and again during setup.

Caller ID remains low assurance. Startup therefore requires exactly one
canonical E.164 caller and a six-to-twelve-digit `TWILIO_VOICE_PIN`. The
adapter freezes both policies for its process lifetime. All tools except the
reviewed `safe_tools` list are sent to Hermes's existing approval queue, but
only the exact configured non-voice destination and owner may decide. The
one-use decision is bound to the voice session, tool-call ID, tool name,
canonical argument digest, destination identity, and expiry. Voice speech,
DTMF, callbacks, and model output cannot decide or redirect it, and no session
or permanent grant is offered. `block_external` remains the stricter option.

The listener binds to loopback. There is no unauthenticated agent endpoint,
outbound call or SMS function, emergency calling path, call recording, or raw
audio persistence. `/healthz` proves the process is alive. `/readyz` returns
200 only after the adapter has a message handler, credentials, allowlist, and
a valid public URL; otherwise it returns 503. Logs use caller and URL digests,
not raw numbers, URLs, tokens, prompts, or frames.

Each call uses its Call SID as a distinct Hermes DM chat and a hashed caller
subject as its user id. Hermes supplies the durable session record, cached
agent, default-profile model/memory/skills/tools, message alternation, and
prompt cache. A call disconnect cancels that call's task and clears all
in-memory transport state. Duration, idle time, setup time, frame size, prompt
size, and concurrency are bounded in `config.yaml`.

## Install without touching the source checkout

Prerequisites:

- Hermes v0.20 running the default profile and its gateway under launchd.
- The existing `TWILIO_ACCOUNT_SID` and primary `TWILIO_AUTH_TOKEN` in the
  profile's `.env`. Do not copy them into another file unless that file is
  owner-only.
- FastAPI and uvicorn in the Hermes environment (included by v0.20).
- ConversationRelay enabled by accepting Twilio's Predictive and Generative
  AI/ML Features Addendum.
- A stable HTTPS/WSS hostname, preferably a dedicated named Cloudflare tunnel;
  or `cloudflared` for the Quick Tunnel supervisor below.

Install from the reviewed local checkout through Hermes's supported plugin
installer. The installer prompts for every missing required secret, including
the PIN, using masked input and saves it to Hermes's secret environment file:

```bash
hermes plugins install 'file:///path/to/hermes-agent#examples/external_plugins/twilio_voice' --enable
```

Do not pass a real secret on a command line. If a required value already exists,
the installer leaves it unchanged; otherwise enter it only at the masked
prompt. Use [`config.example.yaml`](config.example.yaml) only as a field
reference. Configure behavior with `hermes config set` rather than hand-editing
`config.yaml`. The bounded minimum migration uses placeholders here so no
private value is printed by this document:

```bash
hermes config set gateway.platforms.twilio_voice.enabled true
hermes config set gateway.platforms.twilio_voice.extra.public_base_url https://REPLACE_WITH_REVIEWED_VOICE_HOST
hermes config set gateway.platforms.twilio_voice.extra.allowed_callers '["+REPLACE_WITH_REVIEWED_E164"]'
hermes config set gateway.platforms.twilio_voice.extra.trusted_approval_destination '{"platform":"mattermost","account_id":"REPLACE_ACCOUNT","chat_id":"REPLACE_CHANNEL","user_id":"REPLACE_OWNER","thread_id":"REPLACE_THREAD","expires_seconds":120}'
hermes config set gateway.platforms.twilio_voice.extra.action_policy approval_required
hermes config set gateway.platforms.twilio_voice.extra.safe_tools '["clarify","web_search","web_extract"]'
hermes config set gateway.platforms.mattermost.extra.approval_account_id REPLACE_ACCOUNT
hermes config set gateway.platforms.mattermost.extra.reply_mode thread
```

The PIN and existing Twilio credentials remain secrets. Do not echo them into
logs or shell transcripts:

```dotenv
# Already present; do not duplicate or print them.
TWILIO_ACCOUNT_SID=...
TWILIO_AUTH_TOKEN=...

# Required voice PIN. Supply it only through the installer's masked prompt.
TWILIO_VOICE_PIN=...
```

Installing or restarting the launchd-managed Hermes gateway is a deployment
action and was not performed here. The standard Hermes commands are:

```bash
hermes gateway install --force
hermes gateway start
```

After the operator starts it, verify only over loopback:

```bash
curl --fail http://127.0.0.1:8091/healthz
curl --fail http://127.0.0.1:8091/readyz
hermes gateway status
```

Do not expose any other Hermes HTTP/API adapter through this tunnel.

## Preferred stable Cloudflare tunnel

Create a dedicated tunnel and DNS hostname for voice; do not reuse the named
tunnels belonging to other services. Route only that hostname to
`http://127.0.0.1:8091`, set `public_base_url` to its exact externally visible
`https://` origin (including any path prefix), and omit
`runtime_public_url_file`. Cloudflare must preserve the request path and Host.
The configured public URL—not forwarded loopback headers—is the signature
canonicalization source, preventing proxy-header spoofing.

No Cloudflare account configuration or management credential was available in
the assessed environment, so a named tunnel cannot be provisioned from this
artifact. The Quick Tunnel path below is a tested first-deployment option.

## Quick Tunnel supervisor with exact webhook refresh

The live SMS helper was inspected only as a process-supervision pattern. It
starts `cloudflared`; it does not refresh Twilio. This plugin's
[`supervisor.py`](supervisor.py) implements the missing URL discovery and
transactional Voice webhook update.

Copy [`deploy/supervisor.example.yaml`](deploy/supervisor.example.yaml) to an
owner-only behavioral config and ensure its `runtime_public_url_file` exactly
matches the plugin setting. The supervisor:

1. starts a Quick Tunnel to loopback and extracts only a syntactically valid
   `trycloudflare.com` URL from bounded child output;
2. queries Twilio for voice-capable IncomingPhoneNumber resources;
3. permits count-based discovery only for planning; `--apply` requires a
   non-empty, duplicate-free `managed_number_sids` list and verifies every SID
   is an exact voice-capable resource in the configured account with no TwiML
   Application;
4. saves the first pre-migration Voice URL/method rows and runtime URL state in
   a mode-0600 rollback file as the durable baseline for a later operator
   `restore()`;
5. writes the new mode-0600 signature URL state, requires `/readyz` to succeed
   over loopback, then changes only `VoiceUrl` and `VoiceMethod=POST` on those
   exact number SIDs; and
6. before every apply, including a later tunnel rotation, durably records a
   fresh transaction preflight containing the exact current rows and local
   signature/runtime state. It records intent before every provider request,
   rereads every exact target after ambiguous completion, restores that apply's
   immediate preflight, and verifies remote convergence before restoring local
   state. An unproved result remains owner-only `uncertain` state for verified
   restart recovery to the same immediate preflight.

It never changes messaging webhooks or any other number property. It logs only
counts and digests. Credentials are read from the environment or the selected
dotenv file, never CLI arguments. `supervise` is a dry run unless `--apply` is
present:

```bash
chmod 600 /path/to/supervisor.yaml
cd ~/.hermes/plugins/platforms

# Safe commissioning: with `managed_number_sids` empty, this starts a temporary
# Quick Tunnel and performs count-based discovery but cannot authorize apply.
python -m twilio_voice.supervisor supervise \
  --config /path/to/supervisor.yaml \
  --env-file ~/.hermes/.env

# Before apply, obtain the exact IncomingPhoneNumber SIDs from the authenticated
# Twilio Console, place them in the owner-only supervisor config, rerun the dry
# run, and confirm the exact target/change counts. Apply then fails closed if
# any SID was substituted, duplicated, malformed, foreign, or non-voice.
python -m twilio_voice.supervisor supervise \
  --config /path/to/supervisor.yaml \
  --env-file ~/.hermes/.env \
  --apply
```

For launchd, replace every placeholder in
[`deploy/com.hermes.twilio-voice-tunnel.plist.template`](deploy/com.hermes.twilio-voice-tunnel.plist.template).
`__PLUGIN_PARENT__` is the directory containing `twilio_voice`, not the plugin
itself. Use the Hermes virtualenv's absolute Python path, owner-only config,
dotenv, rollback/state directory, and log file. Load the plist only after the
gateway listener is installed. `KeepAlive` restarts the supervisor after URL
rotation or tunnel failure; each start rediscovers the URL and repeats the
exact transaction. Successful rotations retain the first pre-migration
baseline so an operator `restore()` from stable `active` state still returns to
the values from before the first migration. A failed, ambiguous, or interrupted
rotation instead uses its fresh per-apply transaction preflight and returns to
the immediately preceding successful state without overwriting that baseline.

The template includes `--apply`, so installing/loading it is a live mutation.
Review it first. Neither was done during this build.

After review, the exact user-agent commands are:

```bash
cp /path/to/com.hermes.twilio-voice-tunnel.plist \
  ~/Library/LaunchAgents/com.hermes.twilio-voice-tunnel.plist
chmod 600 ~/Library/LaunchAgents/com.hermes.twilio-voice-tunnel.plist
launchctl bootstrap gui/$(id -u) \
  ~/Library/LaunchAgents/com.hermes.twilio-voice-tunnel.plist
launchctl print gui/$(id -u)/com.hermes.twilio-voice-tunnel
```

Those commands are deployment instructions, not commands run by this build.

## Exact Twilio Console setup (manual stable-host path)

Before changing anything, export or record each target number's current Voice
"A call comes in" URL and HTTP method. Do not alter its Messaging section.
Then, for each of the two already-owned voice-capable numbers:

1. Open Twilio Console → Phone Numbers → Manage → Active numbers → the number.
2. Under Voice configuration, set **A call comes in** to **Webhook**.
3. Set the URL to the exact stable public base plus `/twilio/voice`.
4. Set the method to **HTTP POST**, save, and repeat for the other number.

The endpoint returns `<Connect><ConversationRelay>` with the signed WSS URL;
no separate TwiML App is required for number-level configuration. If a number
already points to a TwiML App, stop and review rather than overwriting it. The
Quick Tunnel supervisor intentionally refuses that case.

## Migration and rollback

Migration is reversible and does not touch number ownership or messaging:

1. Record each reviewed IncomingPhoneNumber SID and its Voice URL/method from
   the authenticated provider console; do not rely on a count.
2. Supply the strong PIN through the plugin installer's masked prompt. Configure
   the one reviewed E.164 caller and exact trusted non-voice owner route with
   `hermes config set` as above. Configure the destination adapter's matching
   `approval_account_id` and `reply_mode: thread`; any other reply mode fails
   closed because exact approval-thread delivery cannot be proved.
3. Install/configure the plugin and verify loopback health/readiness. Missing
   or malformed auth/destination configuration must keep `/readyz` closed.
4. Run count-only commissioning with no `--apply`, then populate exact SIDs in
   the owner-only supervisor config and rerun the dry-run. Any mismatch stops.
5. Bring up the stable tunnel or use explicit `supervise --apply`; change only
   the reviewed numbers' inbound Voice webhook URL/method.
6. From the trusted non-voice route, test one unsafe synthetic tool request:
   only `/approve va_…` or `/deny va_…` from the exact owner/account/channel/
   thread may resolve it, once, before expiry. Voice approval phrases remain
   blocked. Place a real call only after separate deployment approval.

For a stable hostname, restore each recorded Voice URL and method in the same
Twilio Console fields, then disable `gateway.platforms.twilio_voice` and the
plugin on the next planned gateway restart.

For a Quick Tunnel transaction, unload the supervisor so it cannot reapply,
then run the explicit restore (both are deployment actions):

```bash
launchctl bootout gui/$(id -u) \
  ~/Library/LaunchAgents/com.hermes.twilio-voice-tunnel.plist
cd ~/.hermes/plugins/platforms
python -m twilio_voice.supervisor restore \
  --config /path/to/supervisor.yaml \
  --env-file ~/.hermes/.env
```

Restore checks account identity, target SID order, rollback-file ownership and
schema; it restores each exact prior Voice URL/method and the prior runtime URL
state. Preserve the rollback file until restoration is verified. Never delete
or overwrite it to force a deployment through a failed integrity check.

## Test and static-check commands

From the Hermes source root:

```bash
python -m pytest -q examples/external_plugins/twilio_voice/tests
python -m compileall -q examples/external_plugins/twilio_voice
python -m ruff check examples/external_plugins/twilio_voice
```

The suite covers documented signature vectors, invalid signatures, allowlist
rejection, PIN gating, malformed/oversized frames, setup binding, fake-Hermes
prompt routing, incremental streaming, interruption, disconnect cleanup,
concurrent-call isolation, phone-text normalization, action-policy propagation,
exact number targeting, owner-only state, partial-apply rollback, URL discovery,
and restoration of previous Voice/runtime settings.
