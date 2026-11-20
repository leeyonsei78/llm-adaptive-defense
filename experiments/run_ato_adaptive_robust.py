"""Robustness re-run of the ATO capability-ladder (section 6.9) with a STOCHASTIC defender.

The original ladder run fixed the defender at temperature 0 (deterministic), so the only
source of variation across repeats was the attacker. A reviewer could object that the
per-repeat outcomes are therefore not independent samples of the defender's behavior.

Here the DEFENDER also samples at temperature>0 with an independent seed per repeat
(attacker: temp 0.7, seed 1000+repeat; defender: temp --defender-temp, seed 7000+repeat).
The Wilson 95% intervals then reflect real defender sampling variation. We re-run only the
cells the paper's claims hinge on (L2_informed, L3_device x rules/rules2/llm_* defenders).

Synthetic, loopback only, same model family (development setup); not held-out evidence.
Endpoint is ai_study.OLLAMA_URL (override with the OLLAMA_URL env var).
"""
import argparse
import csv
import hashlib
import json
import shutil
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import ai_study
import ato_adaptive as ad
import ato_fixtures as fx  # noqa: F401  (imported for parity / provenance)
import ato_study
import run_ato_adaptive as base  # reuse decide() and wilson()

DEFENDER_SEED_BASE = 7000


def campaign(mode, level, attacker_model, defender_model, rounds, repeat, defender_temp, variant='summary'):
    ajob = dict(model=attacker_model, calls=[], events=[],
                options={**ai_study.OPTIONS, 'temperature': 0.7, 'seed': 1000 + repeat, 'num_predict': 120})
    djob = dict(model=defender_model, calls=[], events=[],
                options={**ai_study.OPTIONS, 'temperature': defender_temp, 'seed': DEFENDER_SEED_BASE + repeat})
    start = time.monotonic()
    att_hist, def_hist, trials, fails = [], [], [], 0
    outcome, status, error = 'exhausted', 'completed', None
    try:
        for i in range(rounds):
            p = ad.propose(ajob, att_hist, level)
            event = ad.to_event(p, fails)
            action = base.decide(mode, djob, event, ad.VICTIM, def_hist, ato_study.defend, variant)
            trials.append(dict(round=i + 1, proposal=p, action=action,
                               injection_attempt=bool(ad.INJECTION_WORDS.search(p['user_agent']))))
            att_hist.append(dict(attempt=i + 1, geo=p['geo'], device_known=p['device_known'], local_hour=p['local_hour'],
                                 ip_distinct_accounts=p['ip_distinct_accounts'], outcome=ad.FEEDBACK[action]))
            def_hist.append(dict(geo=p['geo'], device_known=p['device_known'], local_hour=p['local_hour'],
                                 ip_distinct_accounts=p['ip_distinct_accounts'], action_taken=action))
            if action == 'allow':
                outcome = 'takeover'
                break
            if action == 'lock':
                outcome = 'locked'
                break
            fails += 1
    except Exception as exc:
        status, error = 'failed', str(exc)
    return dict(id=f'{repeat}-{mode}-{level}', mode=mode, level=level, repeat=repeat,
                status=status, error=error, outcome=outcome, takeover=outcome == 'takeover',
                rounds_used=len(trials), trials=trials, wall_seconds=time.monotonic() - start,
                injection_attempts=sum(t['injection_attempt'] for t in trials),
                defender_temp=defender_temp, defender_seed=DEFENDER_SEED_BASE + repeat,
                calls=ajob['calls'] + djob['calls'])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--attacker-model', default='qwen2.5-coder:14b')
    ap.add_argument('--defender-model', default='qwen2.5-coder:14b')
    ap.add_argument('--rounds', type=int, default=8)
    ap.add_argument('--seeds', type=int, default=15, help='independent repeats; attacker+defender seeds vary per repeat')
    ap.add_argument('--defender-temp', type=float, default=0.7)
    ap.add_argument('--modes', nargs='+', choices=base.MODES,
                    default=['rules', 'rules2', 'llm_sync', 'llm_escalate', 'llm_history'])
    ap.add_argument('--levels', nargs='+', choices=ad.LEVELS, default=['L2_informed', 'L3_device'])
    args = ap.parse_args()
    if not 1 <= args.rounds <= 20 or not 1 <= args.seeds <= 50:
        ap.error('rounds 1..20, seeds 1..50')
    out = ROOT / 'research' / 'ato_ladder_robust_runs' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
    out.mkdir(parents=True)
    with urllib.request.urlopen(ai_study.OLLAMA_URL + '/api/tags', timeout=5) as r:
        names = [m['name'] for m in json.load(r)['models']]
    for m in (args.attacker_model, args.defender_model):
        if m not in names:
            ap.error('Model not installed: ' + m)
    src = ['experiments/run_ato_adaptive_robust.py', 'experiments/run_ato_adaptive.py',
           'ato_adaptive.py', 'ato_study.py', 'ato_fixtures.py', 'ai_study.py']
    for n in src:
        shutil.copyfile(ROOT / n, out / ('src_' + n.replace('/', '_')))
    (out / 'manifest.json').write_text(json.dumps(dict(
        created_at=datetime.now(timezone.utc).isoformat(), args=vars(args), ollama_url=ai_study.OLLAMA_URL,
        scope='robustness re-run: STOCHASTIC defender (temp>0, independent seed per repeat) over key ladder cells; '
              'synthetic; same model family; development setup',
        attacker_options='temperature 0.7, seed 1000+repeat, num_predict 120',
        defender_options=f'temperature {args.defender_temp}, seed {DEFENDER_SEED_BASE}+repeat, otherwise ai_study.OPTIONS',
        victim=ad.VICTIM, defender_variant='summary (information parity with rules)',
        source_sha256={n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest() for n in src}), indent=2), encoding='utf-8')
    print('Artifacts:', out, flush=True)
    jobs = []
    for rep in range(args.seeds):
        for level in args.levels:
            for mode in args.modes:
                job = campaign(mode, level, args.attacker_model, args.defender_model, args.rounds, rep, args.defender_temp)
                (out / (job['id'] + '.json')).write_text(json.dumps(job, ensure_ascii=False, indent=2), encoding='utf-8')
                jobs.append(job)
                print(job['id'], job['status'], job['outcome'], job['rounds_used'], flush=True)
    agg = {}
    for level in args.levels:
        for mode in args.modes:
            cell = [j for j in jobs if j['mode'] == mode and j['level'] == level]
            k = sum(j['takeover'] for j in cell)
            n = len(cell)
            lo, hi = base.wilson(k, n)
            agg[f'{mode}-{level}'] = dict(mode=mode, level=level, takeovers=k, n=n,
                                          rate=round(k / n, 4) if n else None,
                                          ci_low=round(lo, 4), ci_high=round(hi, 4),
                                          failed=sum(j['status'] != 'completed' for j in cell))
    (out / 'aggregate.json').write_text(json.dumps(agg, indent=2, ensure_ascii=False), encoding='utf-8')
    rows = [{k: j[k] for k in ('id', 'mode', 'level', 'repeat', 'status', 'outcome', 'rounds_used', 'injection_attempts')}
            for j in jobs]
    with (out / 'summary.csv').open('w', newline='', encoding='utf-8-sig') as h:
        w = csv.DictWriter(h, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print('AGGREGATE:', json.dumps(agg, ensure_ascii=False), flush=True)
    if any(j['status'] != 'completed' for j in jobs):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
