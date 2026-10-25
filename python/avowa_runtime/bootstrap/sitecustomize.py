# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Avowa, Inc.
"""Imported automatically by CPython at start-up when this directory is on PYTHONPATH.

`avowa-run` puts it there. Nothing here runs unless AVOWA_AUTO=1, and anything that goes wrong
is swallowed — a telemetry SDK must never be the reason a customer's process fails to boot.

If the app already ships its own sitecustomize.py, ours would shadow it, so we chain: we import
theirs first from the rest of the path before doing anything of our own.
"""
import os
import sys

try:
    _here = os.path.dirname(os.path.abspath(__file__))
    _rest = [p for p in sys.path if os.path.abspath(p or ".") != _here]
    _saved, sys.path[:] = sys.path[:], _rest
    _self = sys.modules.get("sitecustomize")
    try:
        del sys.modules["sitecustomize"]
        import sitecustomize
    except Exception:
        pass
    finally:
        sys.path[:] = _saved
        if _self is not None:
            sys.modules["sitecustomize"] = _self
except Exception:
    pass

try:
    if (os.environ.get("AVOWA_AUTO", "").lower() in ("1", "true", "yes", "on")
            and os.environ.get("AVOWA_DISABLE", "").lower() not in ("1", "true", "yes", "on")):
        import avowa_runtime.auto
except Exception:
    pass
