#!/usr/bin/env python3
"""Print the trusted release manifest (paste into dashboard > Settings > Agent releases).
  python tools/make_manifest.py --source agent           # running from source (hashes the same .py files the agent reports)
  python tools/make_manifest.py dist/SentinelAgent.exe   # frozen build (reports the exe by file name)"""
import hashlib, json, os, sys

def h(p):
    d = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): d.update(b)
    return d.hexdigest()

args = sys.argv[1:]
if not args: sys.exit(__doc__)
out = {}
if args[0] == "--source":
    agent = os.path.abspath(args[1]); pkg = os.path.join(agent, "sentinel")
    for d, _, fs in os.walk(pkg):
        for f in fs:
            if f.endswith(".py"): out[os.path.relpath(os.path.join(d, f), agent).replace("\\", "/")] = h(os.path.join(d, f))
    for f in ("run_agent.py", "sentinel_service.py"):
        if os.path.exists(os.path.join(agent, f)): out[f] = h(os.path.join(agent, f))
else:
    for p in args: out[os.path.basename(p)] = h(p)
print(json.dumps(out, indent=2, sort_keys=True))
