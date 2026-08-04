"""``hermes whatsapp`` subcommand parser.

Extracted verbatim from ``hermes_cli/main.py:main()`` (god-file Phase 2).
Handler injected to avoid importing ``main``.
"""

from __future__ import annotations

from typing import Callable


def build_whatsapp_parser(subparsers, *, cmd_whatsapp: Callable) -> None:
    """Attach the ``whatsapp`` subcommand to ``subparsers``."""
    # =========================================================================
    # whatsapp command
    # =========================================================================
    whatsapp_parser = subparsers.add_parser(
        "whatsapp",
        help="Set up or provision WhatsApp integration",
        description="Configure WhatsApp or provision an auth session with a phone-number pairing code",
    )
    actions = whatsapp_parser.add_subparsers(dest="whatsapp_action")
    provision = actions.add_parser(
        "provision",
        help="Offline phone-number pairing-code provisioning",
        description=(
            "Provision a production auth session offline. The phone number is "
            "read interactively and never placed in argv."
        ),
    )
    provision.add_argument(
        "--role",
        choices=("ordinary", "sensitive"),
        required=True,
        help="Auth session role to provision",
    )
    mode = provision.add_mutually_exclusive_group()
    mode.add_argument(
        "--validate-only",
        action="store_true",
        help="Return non-sensitive session readiness without prompting",
    )
    mode.add_argument(
        "--reprovision",
        action="store_true",
        help="Explicitly provision even when the selected session is ready",
    )
    whatsapp_parser.set_defaults(func=cmd_whatsapp)
