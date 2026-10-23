#!/usr/bin/env python3
"""Poll xray-core Actions run until completed (checks every 180s, up to ~55 min)."""
import sys, time, json, urllib.request
sys.path.insert(0, '/opt/hatch/skills/skill-creator/bin')
from dynamic_credentials import add_surrogate_to_request, read_json_response

API = "https://api.github.com"
REPO = "cien121/xray-core"
CRED = "custom.github-upload"
RUN_ID = sys.argv[1]

def api_get(path):
    r = urllib.request.Request(API + path, method='GET')
    r.add_header('Accept', 'application/vnd.github.v3+json')
    r.add_header('User-Agent', 'Muse-MistAAR')
    add_surrogate_to_request(r, CRED, allowed_hosts=['api.github.com'])
    return read_json_response(urllib.request.urlopen(r))

deadline = time.time() + 55 * 60
last = None
while time.time() < deadline:
    run = api_get(f"/repos/{REPO}/actions/runs/{RUN_ID}")
    st = f"{run['status']}/{run['conclusion']}"
    if st != last:
        print(f"[{time.strftime('%H:%M:%S')}] run {RUN_ID}: {st}", flush=True)
        last = st
    if run['status'] == 'completed':
        print("FINAL:", run['conclusion'])
        print("URL:", run['html_url'])
        break
    time.sleep(180)
else:
    print("TIMEOUT: still not completed")
