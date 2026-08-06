from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path


def test_real_hermes_plugin_loader_config_and_session_isolation(tmp_path):
    """Exercise the actual user-plugin, config, registry, and adapter path."""
    plugin_source = Path(__file__).resolve().parents[1]
    plugin_target = tmp_path / "plugins" / "platforms" / "twilio_voice"
    shutil.copytree(
        plugin_source,
        plugin_target,
        ignore=shutil.ignore_patterns("tests", "__pycache__", "*.pyc"),
    )
    (tmp_path / "config.yaml").write_text(
        textwrap.dedent(
            """
            plugins:
              enabled: [twilio-voice-platform]
            gateway:
              platforms:
                twilio_voice:
                  enabled: true
                  extra:
                    public_base_url: https://voice.example.test
                    allowed_callers: ['+442000000001']
                    trusted_approval_destination:
                      platform: mattermost
                      account_id: reviewed-account
                      chat_id: reviewed-channel
                      user_id: reviewed-owner
                      thread_id: reviewed-thread
                    action_policy: block_external
                    max_concurrent_calls: 2
            """
        ),
        encoding="utf-8",
    )
    script = textwrap.dedent(
        """
        from types import SimpleNamespace

        from gateway.config import Platform, load_gateway_config
        from gateway.platform_registry import platform_registry
        from gateway.session import build_session_key
        from hermes_cli.plugins import discover_plugins, invoke_hook

        discover_plugins()
        entry = platform_registry.get('twilio_voice')
        assert entry is not None and entry.source == 'plugin'
        config = load_gateway_config()
        platform = Platform('twilio_voice')
        platform_config = config.platforms[platform]
        adapter = platform_registry.create_adapter('twilio_voice', platform_config)
        assert adapter is not None
        assert adapter.authorization_is_upstream is True
        assert adapter.voice_config.action_policy == 'block_external'

        first = SimpleNamespace(
            call_sid='CA' + '1' * 32,
            caller='+442000000001',
            session_id='VX' + '3' * 32,
        )
        second = SimpleNamespace(
            call_sid='CA' + '2' * 32,
            caller='+442000000001',
            session_id='VX' + '4' * 32,
        )
        source_one = adapter._source(first)
        source_two = adapter._source(second)
        assert source_one.platform.value == 'twilio_voice'
        assert source_one.chat_id != source_two.chat_id
        assert build_session_key(source_one) != build_session_key(source_two)
        assert '+442000000001' not in source_one.user_id

        invoke_hook('on_session_start', session_id='voice-session', platform='twilio_voice')
        directives = invoke_hook(
            'pre_tool_call',
            tool_name='terminal',
            args={},
            session_id='voice-session',
            tool_call_id='tool-call-1',
        )
        assert directives and directives[0]['action'] == 'block'
        print('PLUGIN_INTEGRATION_OK')
        """
    )
    env = os.environ.copy()
    env.update(
        {
            "HERMES_HOME": str(tmp_path),
            "TWILIO_ACCOUNT_SID": "AC" + "a" * 32,
            "TWILIO_AUTH_TOKEN": "synthetic-test-token",
            "TWILIO_VOICE_PIN": "739155",
        }
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[4],
        env=env,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "PLUGIN_INTEGRATION_OK"
