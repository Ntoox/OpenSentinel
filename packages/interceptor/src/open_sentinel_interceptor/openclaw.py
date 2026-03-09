"""
Sacred Gatekeeper — OpenClaw Adapter

Patches OpenClaw's tool-call dispatcher so every call passes through the
Sacred Gatekeeper interceptor before execution.

Usage (add near the top of your OpenClaw agent setup):
    from sacred_gatekeeper_interceptor.openclaw import patch_openclaw
    patch_openclaw()

Then continue as normal.  Any MEDIUM/HIGH/CRITICAL call will block until
your phone approves it (or auto-deny on timeout / broker unreachable).
"""

from __future__ import annotations

import functools
from typing import Any

from .interceptor import Interceptor

_interceptor = Interceptor()
_patched = False


def patch_openclaw() -> None:
    """Monkey-patch OpenClaw's tool executor with Sacred Gatekeeper.

    Tries to import ``openclaw.tools`` and wrap its ``call`` / ``execute``
    function.  Falls back gracefully if the import path changes between
    OpenClaw versions.
    """
    global _patched
    if _patched:
        return

    try:
        import openclaw.tools as _oc_tools  # type: ignore
        _wrap_module(_oc_tools)
        _patched = True
        print("[Sacred Gatekeeper] OpenClaw tools patched ✓")
        return
    except ImportError:
        pass

    # Older versions exposed the executor on the agent object directly
    try:
        import openclaw.agent as _oc_agent  # type: ignore
        _wrap_module(_oc_agent)
        _patched = True
        print("[Sacred Gatekeeper] OpenClaw agent patched ✓")
        return
    except ImportError:
        pass

    print(
        "[Sacred Gatekeeper] WARNING: Could not locate OpenClaw executor. "
        "Patch not applied — calls will NOT be gated."
    )


def _wrap_module(module: Any) -> None:
    """Wrap the first callable ``call`` or ``execute`` found in *module*."""
    for attr in ("call", "execute", "run_tool", "dispatch"):
        fn = getattr(module, attr, None)
        if fn is not None and callable(fn):
            setattr(module, attr, _make_wrapper(fn, attr))
            return
    raise ImportError(f"No known executor attribute found in {module.__name__}")


def _make_wrapper(original_fn: Any, attr_name: str) -> Any:
    @functools.wraps(original_fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        # Attempt to extract (tool_name, params) from positional / keyword args.
        # OpenClaw typically calls execute(name, params) or execute(tool, **kwargs).
        tool_name: str = ""
        params: dict = {}

        if args:
            tool_name = str(args[0])
        if len(args) >= 2 and isinstance(args[1], dict):
            params = args[1]
        elif kwargs:
            params = kwargs

        if not tool_name:
            tool_name = attr_name  # last-resort fallback

        allowed = _interceptor.intercept(tool_name, params)
        if not allowed:
            raise PermissionError(
                f"[Sacred Gatekeeper] '{tool_name}' was blocked or denied."
            )
        return original_fn(*args, **kwargs)

    return wrapper


# ── Convenience: gated() decorator for manual use ────────────────────────────

def gated(func: Any) -> Any:
    """Decorator for individual OpenClaw tool functions."""
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        params = dict(zip(func.__code__.co_varnames, args))
        params.update(kwargs)
        if _interceptor.intercept(func.__name__, params):
            return func(*args, **kwargs)
        raise PermissionError(
            f"[Sacred Gatekeeper] '{func.__name__}' was blocked or denied."
        )
    return wrapper
