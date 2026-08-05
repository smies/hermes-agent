"""Install-manifest plumbing for bundled desktop installs.

``.hermes-install.json`` is a small, code-scoped marker written next to the
managed checkout (the parent of ``hermes_cli/`` — same anchoring rationale as
``.install_method`` in ``hermes_cli/config.py``: it describes *the running
code*, not ``$HERMES_HOME``, so two installs sharing one data directory can't
poison each other).

It records where a checkout came from and where its updates come from:

    {
      "schemaVersion": 1,
      "installMode": "bundled" | "source",
      "channel": "stable" | "main",
      "pinnedCommit": "<sha>",       # optional
      "pinnedTag": "v0.17.0"         # optional, bundled installs only
    }

Semantics
---------
* ``installMode: "source"`` — the checkout is user-managed; ``hermes update``
  (git pull / tag checkout / ZIP fallback) owns updates. **Absence of the file
  means source mode** — every install that exists today is a source install,
  so back-compat is total and nothing needs migrating.
* ``installMode: "bundled"`` — the checkout was materialized from payloads
  shipped inside the desktop installer. The desktop app owns updates (it
  re-materializes the checkout offline after the app itself updates), so
  ``hermes update`` refuses and points at the in-app updater.
* ``channel`` — ``"main"`` tracks the git main branch (source mode only);
  ``"stable"`` tracks tagged releases. The effective channel resolution lives
  in :func:`resolve_update_channel`; ``update.channel`` in config.yaml can
  override for source installs, while bundled installs are always stable.

Pure-stdlib leaf module: no imports from hermes_cli.config (config imports
would drag the full config machinery into every consumer; the desktop
bootstrap and install scripts also write this file without Python).
"""

import json
import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

INSTALL_MANIFEST_NAME = ".hermes-install.json"
INSTALL_MANIFEST_SCHEMA_VERSION = 1

MODE_SOURCE = "source"
MODE_BUNDLED = "bundled"
_VALID_MODES = (MODE_SOURCE, MODE_BUNDLED)

CHANNEL_MAIN = "main"
CHANNEL_STABLE = "stable"
_VALID_CHANNELS = (CHANNEL_MAIN, CHANNEL_STABLE)

# Sentinel accepted in config.yaml's ``update.channel``: defer to the manifest.
CHANNEL_AUTO = "auto"


def _default_manifest() -> dict:
    """The implicit manifest for a checkout with no ``.hermes-install.json``.

    Source mode on the main channel — i.e. exactly today's behavior, so
    pre-manifest installs (all of them) are unaffected.
    """
    return {
        "schemaVersion": INSTALL_MANIFEST_SCHEMA_VERSION,
        "installMode": MODE_SOURCE,
        "channel": CHANNEL_MAIN,
    }


def install_manifest_path(project_root: Optional[Path] = None) -> Path:
    """Path of the manifest for the running code's install tree."""
    root = project_root if project_root is not None else Path(__file__).parent.parent
    return Path(root).resolve() / INSTALL_MANIFEST_NAME


def read_install_manifest(project_root: Optional[Path] = None) -> dict:
    """Read and sanitize the install manifest.

    Never raises: a missing, unreadable, or malformed file — or one with
    out-of-vocabulary ``installMode``/``channel`` values (e.g. written by a
    FUTURE Hermes with a bigger vocabulary) — degrades to the source/main
    default rather than bricking update logic. Unknown extra keys are
    preserved so round-tripping a future manifest doesn't strip fields.
    """
    path = install_manifest_path(project_root)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return _default_manifest()
    except (OSError, ValueError) as exc:
        logger.warning("Unreadable install manifest at %s (%s); assuming source install", path, exc)
        return _default_manifest()

    if not isinstance(raw, dict):
        logger.warning("Install manifest at %s is not a JSON object; assuming source install", path)
        return _default_manifest()

    manifest = dict(raw)
    if manifest.get("installMode") not in _VALID_MODES:
        manifest["installMode"] = MODE_SOURCE
    if manifest.get("channel") not in _VALID_CHANNELS:
        manifest["channel"] = CHANNEL_MAIN if manifest["installMode"] == MODE_SOURCE else CHANNEL_STABLE
    manifest.setdefault("schemaVersion", INSTALL_MANIFEST_SCHEMA_VERSION)
    return manifest


def write_install_manifest(
    manifest: dict,
    project_root: Optional[Path] = None,
) -> Path:
    """Atomically write the manifest (tmp + rename); returns the path written.

    Validates mode/channel up front — writing garbage is worse than raising,
    because every reader silently degrades garbage to source/main and the
    caller's intent (e.g. marking an install bundled) would be quietly lost.
    """
    if manifest.get("installMode") not in _VALID_MODES:
        raise ValueError(f"invalid installMode: {manifest.get('installMode')!r}")
    if manifest.get("channel") not in _VALID_CHANNELS:
        raise ValueError(f"invalid channel: {manifest.get('channel')!r}")

    payload = dict(manifest)
    payload.setdefault("schemaVersion", INSTALL_MANIFEST_SCHEMA_VERSION)

    path = install_manifest_path(project_root)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)
    return path


def is_bundled_install(project_root: Optional[Path] = None) -> bool:
    """True when the running checkout was materialized from desktop payloads."""
    return read_install_manifest(project_root).get("installMode") == MODE_BUNDLED


def resolve_update_channel(
    config: Optional[dict] = None,
    project_root: Optional[Path] = None,
) -> str:
    """Effective update channel for this install.

    Resolution order:
    1. Bundled installs are ALWAYS ``stable`` — the desktop app re-materializes
       from tagged release payloads; a config override can't change what the
       installer ships. (Ejecting flips the manifest to source mode first.)
    2. ``update.channel`` in config.yaml (``stable`` / ``main``) when set to a
       real channel; ``auto``/empty/unknown fall through.
    3. The manifest's own channel (source default: ``main``).
    """
    manifest = read_install_manifest(project_root)
    if manifest.get("installMode") == MODE_BUNDLED:
        return CHANNEL_STABLE

    configured: Any = None
    if isinstance(config, dict):
        update_cfg = config.get("update")
        if isinstance(update_cfg, dict):
            configured = update_cfg.get("channel")
    if isinstance(configured, str) and configured.strip().lower() in _VALID_CHANNELS:
        return configured.strip().lower()

    return manifest.get("channel", CHANNEL_MAIN)


def format_bundled_update_message() -> str:
    """Refusal text for ``hermes update`` on a bundled install."""
    return (
        "✗ This Hermes install is managed by the Hermes desktop app.\n"
        "\n"
        "The desktop app updates the agent together with itself — use the\n"
        "in-app updater (Settings → Check for updates) instead of `hermes update`.\n"
        "\n"
        "To manage this checkout yourself with `hermes update` (git-based\n"
        "updates), eject it from desktop management first. Ejecting keeps the\n"
        "desktop app auto-updating itself, but leaves the agent checkout to you."
    )
