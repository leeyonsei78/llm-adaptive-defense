"""Hold-out / generalisation run for the financial-API detectors (paper §6.18).

Scores the five detectors on session patterns NOT used while designing them:
  minimal_bola          — read EXACTLY ONE other account (hardest BOLA, no volume)
  cred_stuffing         — many failed logins (API4 resource abuse)
  novel_mass_assignment — privileged fields the fixed allowlist misses (isAdmin,
                          account_limit) -> tests rule brittleness vs LLM generalisation
  benign_own_by_id      — benign: read OWN account by numeric id
  benign_email_update   — benign: update own email

Scored against KNOWN labels (not the target's own violation flags), because some
attacks deliberately bypass the detector's fixed assumptions.

Usage:  python experiments/run_fin_api_holdout.py [--n-rules 12] [--n-llm 6] [--model qwen2.5-coder:14b]
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

TYPES = ['minimal_bola', 'cred_stuffing', 'novel_mass_assignment',
         'benign_own_by_id', 'benign_email_update']


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

    run_dir = ROOT / 'research' / 'fin_api_runs' / ('holdout-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S'))
    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / 'fin_requests.jsonl'

    target = tgt.FinTarget(str(log_path))
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), tgt.make_handler(target))
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f'http://127.0.0.1:{port}'
    time.sleep(0.3)

    for i in range(args.n_rules):
        for t in TYPES:
            atk.HOLDOUT_FUNCS[t](base, f'{t}-{i}')
    httpd.shutdown()

    sessions = dfn.split_sessions(str(log_path))
    res = {t: dict(label=atk.HOLDOUT_LABELS[t], n_rules=0, syntactic=0, context=0,
                   behavioral=0, n_llm=0, llm_ctx=0, llm_beh=0, llm_err=0) for t in TYPES}

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

    print(f'\n=== Fin-API HOLD-OUT / generalisation — model={args.model} ===')
    print('(attack rows: higher=better detection; benign rows: higher=false positives)')
    c = ('session type', 'label', 'syntactic', 'context', 'behavioral', 'llm(ctx)', 'llm(beh)')
    print(f'{c[0]:22} | {c[1]:7} | {c[2]:>9} | {c[3]:>9} | {c[4]:>11} | {c[5]:>9} | {c[6]:>9}')
    print('-' * 95)
    for t in TYPES:
        r = res[t]; n = r['n_rules']; nl = r['n_llm']
        print(f"{t:22} | {r['label']:7} | {r['syntactic']}/{n:<7} | {r['context']}/{n:<7} | "
              f"{r['behavioral']}/{n:<9} | {r['llm_ctx']}/{nl:<7} | {r['llm_beh']}/{nl:<7}")

    out = dict(model=args.model, backend=args.backend,
               run_utc=datetime.now(timezone.utc).isoformat(),
               temperature=dfn.OPTIONS.get('temperature'), seed=dfn.OPTIONS.get('seed'),
               n_rules=args.n_rules, n_llm=args.n_llm, types=TYPES, results=res,
               wilson={t: {k: wilson(res[t][k], res[t]['n_llm' if k.startswith('llm') else 'n_rules'])
                           for k in ('syntactic', 'context', 'behavioral', 'llm_ctx', 'llm_beh')} for t in TYPES},
               run_dir=str(run_dir), note='scored vs KNOWN labels; benign rows are false positives')
    (run_dir / 'results.json').write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')
    print('\nsaved:', run_dir / 'results.json')


if __name__ == '__main__':
    main()
