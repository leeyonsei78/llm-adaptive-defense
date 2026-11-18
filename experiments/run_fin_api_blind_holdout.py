"""Execute + score the INDEPENDENT (blind-authored) fin-API hold-out (paper §6.19).

Reads research/fin_api_blind_holdout.json -- session scripts authored by a fresh
agent that was BLIND to the detectors (it never saw the rule/LLM code). Replays
each session against the synthetic target, then scores the five detectors against
the blind author's labels. This is the strongest circularity check: the attack
author and the detector author are different and mutually blind.

Usage:  python experiments/run_fin_api_blind_holdout.py [--model qwen2.5-coder:14b]
        [--cases research/fin_api_blind_holdout.json] [--no-llm]
"""
import argparse
import json
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_lab import fin_api_target as tgt          # noqa: E402
from agent_lab import fin_api_defender as dfn         # noqa: E402

PW = {'alice': 'alice-pw', 'bob': 'bob-pw', 'carol': 'carol-pw', 'admin': 'admin-pw'}


def _req(base, method, path, session, token=None, form=None):
    url = base.rstrip('/') + path
    headers = {'X-Session': session}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')
    except Exception as e:  # noqa: BLE001
        return None, str(e)


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return (round(max(0.0, c - h), 2), round(min(1.0, c + h), 2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cases', default='research/fin_api_blind_holdout.json')
    ap.add_argument('--model', default='qwen2.5-coder:14b')
    ap.add_argument('--no-llm', action='store_true')
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:  # noqa: BLE001
        pass

    spec = json.loads((ROOT / args.cases).read_text(encoding='utf-8'))
    sessions_spec = spec['sessions']
    labels = {s['id']: s['label'] for s in sessions_spec}
    classes = {s['id']: s.get('class', '?') for s in sessions_spec}

    run_dir = ROOT / 'research' / 'fin_api_runs' / ('blind-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S'))
    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / 'fin_requests.jsonl'

    target = tgt.FinTarget(str(log_path))
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), tgt.make_handler(target))
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f'http://127.0.0.1:{port}'
    time.sleep(0.3)

    for s in sessions_spec:
        sid = s['id']
        token = None
        auth = s.get('auth', 'none')
        if auth and auth != 'none':
            _, body = _req(base, 'POST', '/api/login', sid, form=dict(username=auth, password=PW.get(auth, 'x')))
            try:
                token = json.loads(body).get('token')
            except Exception:  # noqa: BLE001
                token = None
        for c in s.get('calls', []):
            _req(base, c.get('method', 'GET'), c.get('path', '/'), sid, token=token, form=c.get('form'))
    httpd.shutdown()

    traces = dfn.split_sessions(str(log_path))
    detectors = ['syntactic', 'context', 'behavioral', 'llm_ctx', 'llm_beh']
    # tally[detector][label] = [detected_count, total]
    tally = {d: {'attack': [0, 0], 'benign': [0, 0]} for d in detectors}
    by_class = defaultdict(lambda: {d: [0, 0] for d in detectors})
    llm_err = 0

    for s in sessions_spec:
        sid = s['id']; lab = labels[sid]; cls = classes[sid]
        tr = traces.get(sid, [])
        fired = {
            'syntactic': dfn.rule_syntactic(tr)[0],
            'context': dfn.rule_context(tr)[0],
            'behavioral': dfn.rule_behavioral(tr)[0],
        }
        if not args.no_llm:
            for key, reveal in (('llm_ctx', True), ('llm_beh', False)):
                try:
                    v, _ = dfn.llm_detect(tr, args.model, reveal_owner=reveal)
                    fired[key] = (v == 'attack')
                except Exception as e:  # noqa: BLE001
                    llm_err += 1
                    fired[key] = False
                    print(f'  [llm err {sid} {key}] {type(e).__name__}: {e}', file=sys.stderr)
        for d in detectors:
            if d in fired:
                tally[d][lab][1] += 1
                tally[d][lab][0] += int(bool(fired[d]))
                by_class[cls][d][1] += 1
                by_class[cls][d][0] += int(bool(fired[d]))

    n_attack = sum(1 for s in sessions_spec if labels[s['id']] == 'attack')
    n_benign = sum(1 for s in sessions_spec if labels[s['id']] == 'benign')
    print(f'\n=== BLIND independent hold-out — model={args.model} ===')
    print(f'author_note: {spec.get("author_note", "")}')
    print(f'sessions: {len(sessions_spec)} ({n_attack} attack, {n_benign} benign)\n')
    print(f'{"detector":12} | {"attack caught":>22} | {"benign FP":>20}')
    print('-' * 62)
    for d in detectors:
        a, at = tally[d]['attack']
        b, bt = tally[d]['benign']
        print(f'{d:12} | {a}/{at} {wilson(a, at)!s:>14} | {b}/{bt} {wilson(b, bt)!s:>12}')

    out = dict(model=args.model, author_note=spec.get('author_note', ''),
               n_attack=n_attack, n_benign=n_benign, tally=tally,
               by_class={k: v for k, v in by_class.items()}, llm_err=llm_err, run_dir=str(run_dir))
    (run_dir / 'results.json').write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')
    print('\nsaved:', run_dir / 'results.json')


if __name__ == '__main__':
    main()
