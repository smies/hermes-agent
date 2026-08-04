import asyncio
import pytest


def test_browser_whatsapp_authentication_endpoints_are_closed():
    from hermes_cli import web_server as ws

    for operation in (
        ws.start_whatsapp_onboarding(
            ws.WhatsAppOnboardingStart(mode="self-chat", allowed_users="")
        ),
        ws.get_whatsapp_onboarding_status("closed"),
        ws.apply_whatsapp_onboarding(
            "closed", ws.WhatsAppOnboardingApply(mode="bot", allowed_users="")
        ),
    ):
        with pytest.raises(ws.HTTPException) as caught:
            asyncio.run(operation)
        assert caught.value.status_code == 410


