# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Avowa, Inc.
"""`avowa-run <your command>` — instrument a process without touching its code.

    avowa-run uvicorn app:main --host 0.0.0.0 --port 8000
    avowa-run python worker.py
    avowa-run gunicorn -w 4 app:main

In Docker this is a one-line change to CMD, which is why it's the option most teams actually
ship: containers own their entrypoint, and nothing inside the application changes.

It works by putting this package's `bootstrap/` directory on PYTHONPATH. That directory holds a
`sitecustomize.py`, which CPython imports automatically at start-up — before any of the app's own
code runs — so provider SDKs are patched however deep in the import graph they are loaded.

Gunicorn/uvicorn workers are forked or spawned children and inherit the environment, so workers
are instrumented too. The AvowaRuntime's background sender is created per process; each worker
sends its own signals, and Avowa sums them.
"""
import os
import sys


BOOTSTRAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bootstrap")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        sys.stderr.write(__doc__.split("It works by")[0].strip() + "\n")
        return 0 if argv else 2
    if argv[0] == "--init":
        return _init(argv[1:])
    if argv[0] == "--doctor":
        from .auto import _main as _auto_main
        return _auto_main(["--doctor"])

    from . import _disabled
    if _disabled():
        sys.stderr.write("[avowa] AVOWA_DISABLE is set — starting your command without Avowa\n")
        try:
            os.execvp(argv[0], argv)
        except FileNotFoundError:
            sys.stderr.write("[avowa] command not found: %s\n" % argv[0])
            return 127
        return 0

    from . import load_env
    loaded = None
    try:
        loaded = load_env()
    except Exception:
        pass
    from . import _apply_token
    _apply_token()

    env = dict(os.environ)
    existing = env.get("PYTHONPATH")
    if BOOTSTRAP not in (existing or "").split(os.pathsep):
        env["PYTHONPATH"] = BOOTSTRAP + (os.pathsep + existing if existing else "")
    env["AVOWA_AUTO"] = "1"

    if env.get("AVOWA_RUNTIME_KEY"):
        if loaded:
            sys.stderr.write("[avowa] credentials loaded from %s\n" % loaded)
    else:
        sys.stderr.write(
            "[avowa] no credentials found — your app will start normally, but no signals will be "
            "sent.\n"
            "        Looked for AVOWA_RUNTIME_KEY in the environment, and for avowa.env / .env in\n"
            "        %s and its parents.\n"
            "        Fix (either one):\n"
            "          • run `avowa init <setup-token>` in this directory, or\n"
            "          • export AVOWA_TOKEN=...\n"
            "        On macOS/Linux it must be `export VAR=value` — plain `set VAR=value` is\n"
            "        Windows CMD syntax and silently does nothing in bash/zsh.\n"
            % os.getcwd())

    try:
        os.execvpe(argv[0], argv, env)
    except FileNotFoundError:
        sys.stderr.write("[avowa] command not found: %s\n" % argv[0])
        return 127


def _init(args):
    from .cli import init
    return init(args)


if __name__ == "__main__":
    sys.exit(main())
