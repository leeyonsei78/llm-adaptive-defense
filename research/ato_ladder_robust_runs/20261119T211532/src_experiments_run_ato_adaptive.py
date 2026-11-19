"""Adaptive LLM attacker vs ATO defenders over an attacker-capability ladder (synthetic, local).
Development setup; same model family for attacker and defender; not held-out evidence.

Capability ladder (declared before the run):
  L1_cred      password only
  L2_informed  + victim home country and usual hours
  L3_device    + stolen browser session, may present the victim's known device
Defender information parity: every LLM defender receives the same fields the rules use ('summary' variant).
"""
import argparse
import csv
import hashlib
import json
import math
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
import ato_fixtures as fx
import ato_study

MODES = ('none', 'rules', 'rules2', 'llm_sync', 'llm_escalate', 'llm_history')
SEVERITY = {a: i for i, a in enumerate(fx.ACTIONS)}


def decide(mode, djob, event, profile, history, defend, variant='summary'):
    rule = fx.rules(event, profile)
    if mode == 'none':
        return 'allow'
    if mode == 'rules':
        return rule
    if mode == 'rules2':
        return fx.rules2(event, profile)
    if mode == 'llm_sync':
        return defend(djob, event, profile, variant)['action']
    if mode == 'llm_escalate':
        return max(rule, defend(djob, event, profile, variant)['action'], key=SEVERITY.get)
    if mode == 'llm_history':
        return defend(djob, event, profile, variant, 'baseline', history)['action']
    raise ValueError(mode)


def campaign(mode, level, attacker_model, defender_model, rounds, repeat, attacker_temp=0.7,
             attacker=None, defend=None, variant='summary'):
    attacker = attacker or ad.propose
    defend = defend or ato_study.defend
    ajob = dict(model=attacker_model, calls=[], events=[], options={**ai_study.OPTIONS, 'temperature': attacker_temp,
                'seed': 1000 + repeat, 'num_predict': 120})
    djob = dict(model=defender_model, calls=[], events=[])
    start = time.monotonic()
    att_hist, def_hist, trials, fails = [], [], [], 0
    outcome, status, error = 'exhausted', 'completed', None
    try:
        for i in range(rounds):
            p = attacker(ajob, att_hist, level)
            event = ad.to_event(p, fails)
            action = decide(mode, djob, event, ad.VICTIM, def_hist, defend, variant)
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
                calls=ajob['calls'] + djob['calls'])


def benign_friction(mode, model, defend=None, variant='summary'):
    """The same defender on the 20 benign dev cases (episode events in order)."""
    defend = defend or ato_study.defend
    djob = dict(model=model, calls=[], events=[])
    total = chal = locks = n = 0
    for c in (c for c in fx.CASES if c['label'] == 'benign'):
        hist = []
        for e in c['events']:
            a = decide(mode, djob, e, c['profile'], hist, defend, variant)
            hist.append(dict(geo=e['geo'], device_known=e['device_known'], local_hour=e['local_hour'],
                             ip_distinct_accounts=e['ip_distinct_accounts'], action_taken=a))
            total += fx.FRICTION[a]
            chal += a == 'challenge'
            locks += a == 'lock'
            n += 1
    return dict(mode=mode, benign_events=n, benign_challenges=chal, benign_locks=locks, benign_friction=total)


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--attacker-model', default='qwen2.5-coder:14b')
    ap.add_argument('--defender-model', default='qwen2.5-coder:14b')
    ap.add_argument('--rounds', type=int, default=8)
    ap.add_argument('--repeats', type=int, default=12)
    ap.add_argument('--modes', nargs='+', choices=MODES, default=list(MODES))
    ap.add_argument('--levels', nargs='+', choices=ad.LEVELS, default=list(ad.LEVELS))
    args = ap.parse_args()
    if not 1 <= args.rounds <= 20 or not 1 <= args.repeats <= 50:
        ap.error('rounds 1..20, repeats 1..50')
    out = ROOT / 'research' / 'ato_ladder_runs' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
    out.mkdir(parents=True)
    with urllib.request.urlopen('http://127.0.0.1:11434/api/tags', timeout=5) as r:
        names = [m['name'] for m in json.load(r)['models']]
    for m in (args.attacker_model, args.defender_model):
        if m not in names:
            ap.error('Model not installed: ' + m)
    src = ['experiments/run_ato_adaptive.py', 'ato_adaptive.py', 'ato_study.py', 'ato_fixtures.py', 'ai_study.py']
    for n in src:
        shutil.copyfile(ROOT / n, out / ('src_' + n.replace('/', '_')))
    (out / 'manifest.json').write_text(json.dumps(dict(
        created_at=datetime.now(timezone.utc).isoformat(), args=vars(args),
        scope='adaptive LLM attacker vs defenders over capability ladder; synthetic; same model family; development setup',
        attacker_options='temperature 0.7, seed 1000+repeat, num_predict 120', defender_options=ai_study.OPTIONS,
        victim=ad.VICTIM, defender_variant='summary (information parity with rules)',
        source_sha256={n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest() for n in src}), indent=2), encoding='utf-8')
    print('Artifacts:', out, flush=True)
    jobs = []
    for rep in range(args.repeats):
        for level in args.levels:
            for mode in args.modes:
                job = campaign(mode, level, args.attacker_model, args.defender_model, args.rounds, rep)
                (out / (job['id'] + '.json')).write_text(json.dumps(job, ensure_ascii=False, indent=2), encoding='utf-8')
                jobs.append(job)
                print(job['id'], job['status'], job['outcome'], job['rounds_used'], flush=True)
    rows = [{k: j[k] for k in ('id', 'mode', 'level', 'repeat', 'status', 'outcome', 'rounds_used', 'injection_attempts')}
            for j in jobs]
    with (out / 'summary.csv').open('w', newline='', encoding='utf-8-sig') as h:
        w = csv.DictWriter(h, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    friction = [benign_friction(m, args.defender_model) for m in args.modes if m != 'none']
    (out / 'benign_friction.json').write_text(json.dumps(friction, indent=2), encoding='utf-8')
    if any(j['status'] != 'completed' for j in jobs):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
