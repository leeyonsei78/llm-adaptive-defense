"""Run the financial-API attack/detection experiment (OWASP API business-logic).

Starts the synthetic fin-api target on loopback, generates benign + five attack
session types (real HTTP), then scores five detectors per session type:
rule_syntactic, rule_context, rule_behavioral, llm_detect(context),
llm_detect(behavioural). A §6.12-style rule-vs-LLM comparison extended to OWASP
API Top-10 business-logic attacks (no payload signature).

Usage:  python experiments/run_fin_api_detection.py [--n-rules 12] [--n-llm 6] [--model qwen2.5-coder:14b]
"""
import argparse
import json
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_lab import fin_api_target as tgt          # noqa: E402
from agent_lab import fin_api_attacker as atk         # noqa: E402
from agent_lab import fin_api_defender as dfn         # noqa: E402

BENIGN_USERS = [('alice', 'alice-pw'), ('bob', 'bob-pw'), ('carol', 'carol-pw')]
TYPES = ['benign', 'bola', 'scraping_bola', 'mass_assignment', 'bfla', 'transfer_abuse']


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return (round(max(0.0, centre - half), 2), round(min(1.0, centre + half), 2))


def start_target(log_path):
    target = tgt.FinTarget(log_path)
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), tgt.make_handler(target))
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, port


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--n-rules', type=int, default=12)
    ap.add_argument('--n-llm', type=int, default=6)
    ap.add_argument('--model', default='qwen2.5-coder:14b')
    ap.add_argument('--backend', choices=('ollama', 'openai'), default='ollama',
                    help="LLM backend: 'ollama' (local open model) or 'openai' (hosted strong model)")
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:  # noqa: BLE001
        pass

    run_dir = ROOT / 'research' / 'fin_api_runs' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / 'fin_requests.jsonl'

    httpd, port = start_target(str(log_path))
    base = f'http://127.0.0.1:{port}'
    time.sleep(0.3)

    for i in range(args.n_rules):
        u, pw = BENIGN_USERS[i % len(BENIGN_USERS)]
        atk.benign_session(base, f'benign-{i}', user=u, pw=pw)
        atk.bola_session(base, f'bola-{i}')
        atk.scraping_bola_session(base, f'scraping_bola-{i}')
        atk.mass_assignment_session(base, f'mass_assignment-{i}')
        atk.bfla_session(base, f'bfla-{i}')
        atk.transfer_abuse_session(base, f'transfer_abuse-{i}')
    httpd.shutdown()

    sessions = dfn.split_sessions(str(log_path))
    res = {t: dict(n_rules=0, syntactic=0, context=0, behavioral=0,
                   n_llm=0, llm_ctx=0, llm_beh=0, llm_err=0) for t in TYPES}

    for t in TYPES:
        ids = sorted((s for s in sessions if s.startswith(t + '-')),
                     key=lambda s: int(s.rsplit('-', 1)[1]))
        for rank, sid in enumerate(ids):
            tr = sessions[sid]
            r = res[t]
            r['n_rules'] += 1
            r['syntactic'] += int(dfn.rule_syntactic(tr)[0])
            r['context'] += int(dfn.rule_context(tr)[0])
            r['behavioral'] += int(dfn.rule_behavioral(tr)[0])
            if rank < args.n_llm:
                r['n_llm'] += 1
                for key, reveal in (('llm_ctx', True), ('llm_beh', False)):
                    try:
                        v, _ = dfn.llm_detect(tr, args.model, reveal_owner=reveal,
                                              backend=args.backend)
                        r[key] += int(v == 'attack')
                    except Exception as e:  # noqa: BLE001
                        r['llm_err'] += 1
                        print(f'  [llm err {sid} {key}] {type(e).__name__}: {e}', file=sys.stderr)

    # report
    print(f'\n=== Financial-API detection (OWASP business-logic) — model={args.model} '
          f'backend={args.backend} ===')
    cols = ('session type', 'syntactic', 'context', 'behavioral', 'llm(ctx)', 'llm(beh)')
    print(f'{cols[0]:16} | {cols[1]:>9} | {cols[2]:>9} | {cols[3]:>11} | {cols[4]:>9} | {cols[5]:>9}')
    print('-' * 80)
    for t in TYPES:
        r = res[t]; n = r['n_rules']; nl = r['n_llm']
        tag = t + (' (FP)' if t == 'benign' else '')
        print(f"{tag:16} | {r['syntactic']}/{n:<7} | {r['context']}/{n:<7} | "
              f"{r['behavioral']}/{n:<9} | {r['llm_ctx']}/{nl:<7} | {r['llm_beh']}/{nl:<7}")

    out = dict(model=args.model, backend=args.backend,
               run_utc=datetime.now(timezone.utc).isoformat(),
               temperature=dfn.OPTIONS.get('temperature'), seed=dfn.OPTIONS.get('seed'),
               n_rules=args.n_rules, n_llm=args.n_llm, types=TYPES,
               results=res, wilson={t: dict(
                   syntactic=wilson(res[t]['syntactic'], res[t]['n_rules']),
                   context=wilson(res[t]['context'], res[t]['n_rules']),
                   behavioral=wilson(res[t]['behavioral'], res[t]['n_rules']),
                   llm_ctx=wilson(res[t]['llm_ctx'], res[t]['n_llm']),
                   llm_beh=wilson(res[t]['llm_beh'], res[t]['n_llm'])) for t in TYPES},
               run_dir=str(run_dir),
               note='detection=attack verdict; benign row is false positives')
    (run_dir / 'results.json').write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')
    print('\nsaved:', run_dir / 'results.json')


if __name__ == '__main__':
    main()
