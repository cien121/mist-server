#!/usr/bin/env python3
"""Download libv2ray-mist artifact zip for a run, verify strings, then clean up.
Usage: dl_verify.py <run_id>
/tmp only has 512MB: stream to disk, verify, delete immediately."""
import sys, os, json, shutil, subprocess, urllib.request, urllib.error, zipfile
sys.path.insert(0, '/opt/hatch/skills/skill-creator/bin')
from dynamic_credentials import add_surrogate_to_request, read_json_response, read_response_body

API = "https://api.github.com"
REPO = "cien121/xray-core"
CRED = "custom.github-upload"
RUN_ID = sys.argv[1]
TMP = "/tmp/mist_aar_check"

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def api_get(path):
    r = urllib.request.Request(API + path, method='GET')
    r.add_header('Accept', 'application/vnd.github.v3+json')
    r.add_header('User-Agent', 'Muse-MistAAR')
    add_surrogate_to_request(r, CRED, allowed_hosts=['api.github.com'])
    return read_json_response(urllib.request.urlopen(r))

def download(url, dest):
    opener = urllib.request.build_opener(_NoRedirect())
    req = urllib.request.Request(url)
    req.add_header('User-Agent', 'Muse-MistAAR')
    add_surrogate_to_request(req, CRED, allowed_hosts=['api.github.com'])
    try:
        resp = opener.open(req)
        stream = resp  # no redirect (unlikely)
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308):
            loc = e.headers.get('Location')
            print("redirect ->", loc[:80], "...")
            stream = urllib.request.urlopen(urllib.request.Request(loc))
        else:
            raise
    with open(dest, 'wb') as f:
        shutil.copyfileobj(stream, f, length=1024 * 256)
    print("saved", dest, os.path.getsize(dest), "bytes")

arts = api_get(f"/repos/{REPO}/actions/runs/{RUN_ID}/artifacts?per_page=20")['artifacts']
print("artifacts:", [(a['id'], a['name'], a['size_in_bytes']) for a in arts])
art = next(a for a in arts if 'mist' in a['name'].lower())
os.makedirs(TMP, exist_ok=True)
zpath = os.path.join(TMP, "artifact.zip")
download(f"{API}/repos/{REPO}/actions/artifacts/{art['id']}/zip", zpath)

with zipfile.ZipFile(zpath) as z:
    print("zip contents:", z.namelist())
    z.extractall(TMP)

aar = next(f for f in os.listdir(TMP) if f.endswith('.aar'))
aar_path = os.path.join(TMP, aar)
print("AAR:", aar, os.path.getsize(aar_path), "bytes")
subprocess.run(['unzip', '-o', '-q', aar_path, '-d', os.path.join(TMP, 'aar')], check=True)
so = os.path.join(TMP, 'aar', 'jni', 'arm64-v8a', 'libgojni.so')
out = subprocess.run(['strings', so], capture_output=True, text=True).stdout
mist_n = out.count('proxy/mist')
utls_n = out.count('hellochrome_155')
print("RESULT proxy/mist hits:", mist_n)
print("RESULT hellochrome_155 hits:", utls_n)
print("RESULT", "PASS" if (mist_n > 0 and utls_n > 0) else "FAIL")

shutil.rmtree(TMP, ignore_errors=True)
print("cleaned", TMP)
