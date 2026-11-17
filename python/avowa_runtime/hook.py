# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Avowa, Inc.
"""Imported by `avowa_auto.pth` when a Python process starts and has opted in.

The .pth line only decides whether this is worth importing at all (a token, AVOWA_AUTO, or an
avowa.env beside the app). The real decision is made here, after the env file has been read:
instrument only when `auto_wanted()` says so. Anything that goes wrong is swallowed. An evidence
SDK must never be the reason a process fails to start.
"""
try:
    import os as _os
    import sys as _sys
    from . import _autoload_env, auto_wanted
    _argv = getattr(_sys, "argv", None) or [""]
    _tool = _os.path.basename(_argv[0]) in ("avowa", "avowa-run", "pip", "pip3")
    _autoload_env()
    if auto_wanted() and not _tool:
        from . import auto
except Exception:
    pass
