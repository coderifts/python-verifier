"""1129 — unified (token, opts) with opts['ctx'] / opts['intended']."""
import warnings

_warned = set()


def warn_once(name):
    if name in _warned:
        return
    _warned.add(name)
    warnings.warn(
        f"DEPRECATION: {name}(token, ctx, opts) is deprecated; use {name}(token, {{'ctx': ..., 'intended': ...}}). "
        "This warning is emitted once.",
        DeprecationWarning,
        stacklevel=3,
    )


def split3(name, ctx, opts):
    if opts is not None:
        warn_once(name)
        return ctx or {}, opts or {}
    if isinstance(ctx, dict) and ("ctx" in ctx or "intended" in ctx or "envelope" in ctx):
        return ctx.get("ctx") or {}, ctx
    return ctx or {}, {}


def reset_warned_for_test():
    _warned.clear()
