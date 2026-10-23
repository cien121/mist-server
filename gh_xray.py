#!/usr/bin/env python3
"""GitHub API helper for cien121/xray-core (mist branch): dispatch, runs, logs, artifacts."""
import sys, json, base64, urllib.request, urllib.error
sys.path.insert(0, '/opt/hatch/skills/skill-creator/bin')
from dynamic_credentials import add_surrogate_to_request, read_json_response, read_response_body

API = "https://api.github.com"
OWNER, REPO = "cien121", "xray-core"
CRED = "custom.github-upload"

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def _req(method, url, data=None, raw=False):
    req = urllib.request.Request(url, method=method)
    req.add_header('Accept', 'application/vnd.github.v3+json')
    req.add_header('User-Agent', 'Muse-MistAAR')
    add_surrogate_to_request(req, CRED, allowed_hosts=['api.github.com'])
    body = json.dumps(data).encode() if data is not None else None
    if body:
        req.add_header('Content-Type', 'application/json')
    if raw:
        return urllib.request.urlopen(req, body)
    return read_json_response(urllib.request.urlopen(req, body))

def api_get(path):
    return _req('GET', API + path)

def api_post(path, data):
    return _req('POST', API + path, data)

def get_job_logs(job_id):
    opener = urllib.request.build_opener(_NoRedirect())
    req = urllib.request.Request(f"{API}/repos/{OWNER}/{REPO}/actions/jobs/{job_id}/logs")
    req.add_header('User-Agent', 'Muse-MistAAR')
    add_surrogate_to_request(req, CRED, allowed_hosts=['api.github.com'])
    try:
        return read_response_body(opener.open(req)).decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308):
            loc = e.headers.get('Location')
            blob = urllib.request.Request(loc)
            blob.add_header('User-Agent', 'Muse-MistAAR')
            return read_response_body(urllib.request.urlopen(blob)).decode('utf-8', errors='replace')
        raise

if __name__ == '__main__':
    cmd = sys.argv[1]
    if cmd == 'head':
        branch = sys.argv[2] if len(sys.argv) > 2 else 'mist'
        ref = api_get(f"/repos/{OWNER}/{REPO}/git/ref/heads/{branch}")
        print(ref['object']['sha'])
    elif cmd == 'runs':
        r = api_get(f"/repos/{OWNER}/{REPO}/actions/runs?per_page=10")
        for run in r['workflow_runs']:
            print(run['id'], run['head_sha'][:8], run['status'], run['conclusion'],
                  run['created_at'], run['name'], run['head_branch'])
    elif cmd == 'run':
        run = api_get(f"/repos/{OWNER}/{REPO}/actions/runs/{sys.argv[2]}")
        print(run['id'], run['head_sha'][:8], run['status'], run['conclusion'],
              run['created_at'], run.get('updated_at'), run['name'])
    elif cmd == 'jobs':
        r = api_get(f"/repos/{OWNER}/{REPO}/actions/runs/{sys.argv[2]}/jobs?per_page=20")
        for j in r['jobs']:
            print(j['id'], j['status'], j.get('conclusion'), j['name'])
    elif cmd == 'logs':
        print(get_job_logs(sys.argv[2]))
    elif cmd == 'dispatch':
        api_post(f"/repos/{OWNER}/{REPO}/actions/workflows/{sys.argv[2]}/dispatches",
                 {"ref": sys.argv[3]})
        print("dispatched")
    elif cmd == 'artifacts':
        r = api_get(f"/repos/{OWNER}/{REPO}/actions/runs/{sys.argv[2]}/artifacts?per_page=20")
        for a in r['artifacts']:
            print(a['id'], a['name'], a['size_in_bytes'], a['archive_download_url'])
