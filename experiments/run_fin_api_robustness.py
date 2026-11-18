"""Multi-seed robustness sweep for the fin-API LLM detector (paper §6.17 note).

The rule detectors are deterministic; the only stochastic component is the LLM.
This sweeps the LLM (context mode -- the deployable one) across several seeds at a
non-zero temperature and reports per-seed detection rate plus mean/range, so the
"temp 0, not statistical" caveat on §6.17/§6.18 can be replaced by a measured
stability band.

Usage:  python experiments/run_fin_api_robustness.py [--n-llm 5] [--seeds 5] [--temp 0.7] [--model qwen2.5-coder:14b]
"""
import argparse
import json
import statistics
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

TYPES = ['benign', 'bola', 'scraping_bola', 'mass_assignment', 'bfla', 'transfer_abuse']


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--n-llm', type=int, default=5)
    ap.add_argument('--seeds', type=int, default=5)
    ap.add_argument('--temp', type=float, default=0.7)
    ap.add_argument('--model', default='qwen2.5-coder:14b')
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:  # noqa: BLE001
        pass

    run_dir = ROOT / 'research' / 'fin_api_runs' / ('robust-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S'))
    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / 'fin_requests.jsonl'

    target = tgt.FinTarget(str(log_path))
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), tgt.make_handler(target))
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f'http://127.0.0.1:{port}'
    time.sleep(0.3)
    for i in range(args.n_llm):
        for t in TYPES:
            atk.SESSION_FUNCS[t](base, f'{t}-{i}')
    httpd.shutdown()

    sessions = dfn.split_sessions(str(log_path))
    seeds = list(range(1, args.seeds + 1))
    per = {t: {s: 0 for s in seeds} for t in TYPES}
    errs = 0
    for t in TYPES:
        ids = sorted((x for x in sessions if x.startswith(t + '-')), key=lambda s: int(s.rsplit('-', 1)[1]))
        for s in seeds:
            for sid in ids:
                try:
                    v, _ = dfn.llm_detect(sessions[sid], args.model, reveal_owner=True,
                                          temperature=args.temp, seed=s)
                    per[t][s] += int(v == 'attack')
                except Exception as e:  # noqa: BLE001
                    errs += 1
                    print(f'  [err {sid} seed{s}] {type(e).__name__}: {e}', file=sys.stderr)

    print(f'\n=== Fin-API LLM robustness (context mode) — model={args.model}, temp={args.temp}, '
          f'seeds={seeds}, n={args.n_llm}/type ===')
    print(f'{"session type":16} | per-seed detections (/%d) | mean | range' % args.n_llm)
    print('-' * 70)
    summary = {}
    for t in TYPES:
        vals = [per[t][s] for s in seeds]
        mean = round(statistics.mean(vals), 2)
        summary[t] = dict(per_seed=vals, mean=mean, min=min(vals), max=max(vals), n=args.n_llm)
        fp = ' (FP)' if t == 'benign' else ''
        print(f'{t + fp:16} | {str(vals):24} | {mean:>4} | [{min(vals)},{max(vals)}]')

    out = dict(model=args.model, temperature=args.temp, seeds=seeds, n=args.n_llm,
               llm_errors=errs, summary=summary, run_dir=str(run_dir),
               note='LLM context-mode detections per seed; benign=false positives; rules are deterministic')
    (run_dir / 'results.json').write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')
    print('\nsaved:', run_dir / 'results.json')


if __name__ == '__main__':
    main()
