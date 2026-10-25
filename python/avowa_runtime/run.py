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
            "          • copy avowa.env from your SDK download into this directory, or\n"
            "          • export AVOWA_RUNTIME_KEY=... AVOWA_RUNTIME_SECRET=...\n"
            "        On macOS/Linux it must be `export VAR=value` — plain `set VAR=value` is\n"
            "        Windows CMD syntax and silently does nothing in bash/zsh.\n"
            % os.getcwd())

    try:
        os.execvpe(argv[0], argv, env)
    except FileNotFoundError:
        sys.stderr.write("[avowa] command not found: %s\n" % argv[0])
        return 127


if __name__ == "__main__":
    sys.exit(main())


def _init(args):
    import json
    import os
    import stat
    import urllib.request
    if not args or args[0].startswith("-"):
        sys.stderr.write("usage: avowa-run --init <setup-token> [--api https://api.avowa.ai]\n")
        return 2
    token = args[0]
    api = (os.getenv("AVOWA_BASE_URL") or "https://api.avowa.ai").rstrip("/")
    if "--api" in args:
        api = args[args.index("--api") + 1].rstrip("/")
    from . import _checked_base
    api, problem = _checked_base(api)
    if problem:
        sys.stderr.write(problem.replace("AVOWA_BASE_URL", "--api") + ".\n")
        return 2
    req = urllib.request.Request(api + "/public/sdk/setup", data=json.dumps({"token": token}).encode(),
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "avowa-runtime-python (+https://avowa.ai)"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            creds = json.loads(r.read())
    except Exception as e:
        code = getattr(e, "code", None)
        if code == 404:
            sys.stderr.write("That setup token is invalid, expired (24h) or already used — generate a new one in the console.\n")
        else:
            sys.stderr.write("Could not reach %s (%s). Pass --api with your Avowa API URL.\n" % (api, e))
        return 1
    if creds.get("connector_id") != "runtime_sdk":
        sys.stderr.write("That token belongs to a Collector connection, not the Runtime SDK — use avowa-collector.pyz init.\n")
        return 1
    base, problem = _checked_base(creds.get("base_url") or api)
    if problem:
        sys.stderr.write("The server returned an unsafe API URL (%s); nothing was written.\n" % problem)
        return 1
    path = os.path.join(os.getcwd(), "avowa.env")
    text = ("# Avowa Runtime SDK — credentials for this connection. Keep private, server-side only.\n"
            "# Written by `avowa-run --init`. The SDK reads this file from the directory you start your app from.\n"
            "AVOWA_RUNTIME_KEY=%s\nAVOWA_RUNTIME_SECRET=%s\nAVOWA_BASE_URL=%s\n"
            % (creds["ingest_token"], creds.get("ingest_secret") or "", base))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    print("✓ connected to %s (%s) · credentials in %s (0600)" % (creds.get("label") or "Avowa Runtime SDK", creds.get("environment", "prod"), path))
    print("Next: start your app with `avowa-run <your usual command>` — then `avowa-run --doctor` to confirm the server sees it.")
    return 0
