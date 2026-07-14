import builtins

import guard_core


def test_mute_pydantic_instrumentation_is_noop_without_agent_extra(
    monkeypatch: object,
) -> None:
    """When the guard-agent extra is not installed, muting the telemetry models'
    pydantic-plugin instrumentation must be a clean no-op, not an ImportError."""
    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "guard_agent.models":
            raise ImportError("guard-agent extra not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)  # type: ignore[attr-defined]

    # Must return cleanly without raising.
    guard_core._mute_pydantic_plugin_instrumentation()
