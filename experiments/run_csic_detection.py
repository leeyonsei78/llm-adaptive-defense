"""Run external-benchmark detection on the HTTP Dataset CSIC 2010 (out-of-synthetic generalization).

Scores signature-rule vs LLM (local Ollama or hosted OpenAI) on a balanced sample of the public
CSIC-2010 classification set (label 0=normal, 1=anomalous). Reports recall (attacks caught), false-
positive rate (normal flagged), precision, accuracy and Wilson 95% CIs.

Usage:
  python experiments/run_csic_detection.py --n-rules 1000 --n-llm 100 --model qwen2.5-coder:14b
  python experiments/run_csic_detection.py --skip-rules --n-llm 100 --model gpt-5-2025-08-07 --backend openai
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd                                  # noqa: E402
from agent_lab import csic_detect as cd              # noqa: E402


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return (round(max(0.0, centre - half), 3), round(min(1.0, centre + half), 3))


def balanced(df, n, seed):
    half = n // 2
    atk = df[df.label == 1].sample(n=min(half, int((df.label == 1).sum())), random_state=seed)
    ben = df[df.label == 0].sample(n=min(half, int((df.label == 0).sum())), random_state=seed)
    return atk, ben


def metrics(tp, natk, fp, nben):
    rec = tp / natk if natk else 0.0
    fpr = fp / nben if nben else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    acc = (tp + (nben - fp)) / (natk + nben) if (natk + nben) else 0.0
    return dict(recall=round(rec, 3), recall_ci=wilson(tp, natk),
                fp_rate=round(fpr, 3), fp_ci=wilson(fp, nben),
                precision=round(prec, 3), accuracy=round(acc, 3))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--parquet', default='research/csic2010/test.parquet')
    ap.add_argument('--n-rules', type=int, default=1000)
    ap.add_argument('--n-llm', type=int, default=100)
    ap.add_argument('--model', default='qwen2.5-coder:14b')
    ap.add_argument('--backend', choices=('ollama', 'openai'), default='ollama')
    ap.add_argument('--seed', type=int, default=20261126)
    ap.add_argument('--skip-rules', action='store_true')
    ap.add_argument('--all-methods', action='store_true',
                    help='include POST/PUT (whose bodies are truncated in this mirror); default GET-only')
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:  # noqa: BLE001
        pass

    df = pd.read_parquet(ROOT / args.parquet)
    scope = 'all-methods'
    if not args.all_methods:
        # The mirror truncates POST/PUT bodies (attack payloads absent); GET keeps the full
        # request target (path+query) where GET-attack payloads live -> fair rule-vs-LLM scope.
        df = df[df.requests.str.startswith('GET ')].copy()
        scope = 'GET-only'
    n_norm = int((df.label == 0).sum())
    n_anom = int((df.label == 1).sum())
    print(f'CSIC-2010 loaded [{scope}]: {len(df)} rows ({n_norm} normal / {n_anom} anomalous) from {args.parquet}')

    out = dict(dataset='CSIC-2010 (HF bridge4/CSIC2010_dataset_classification, test split)',
               scope=scope, model=args.model, backend=args.backend, seed=args.seed,
               run_utc=datetime.now(timezone.utc).isoformat(),
               temperature=cd.OPTIONS.get('temperature'), results={})

    # --- signature rule (free, larger n) ---
    if not args.skip_rules:
        atk, ben = balanced(df, args.n_rules, args.seed)
        r_tp = int(sum(cd.rule_signature(x) for x in atk.requests))
        r_fp = int(sum(cd.rule_signature(x) for x in ben.requests))
        m = metrics(r_tp, len(atk), r_fp, len(ben))
        out['results']['rule_signature'] = dict(attack_caught=[r_tp, len(atk)],
                                                 benign_fp=[r_fp, len(ben)], **m)
        print(f"\n[rule_signature]  recall={r_tp}/{len(atk)} ({m['recall']}) {m['recall_ci']} | "
              f"FP={r_fp}/{len(ben)} ({m['fp_rate']}) {m['fp_ci']} | prec={m['precision']} acc={m['accuracy']}")

    # --- LLM (local or OpenAI) ---
    atk, ben = balanced(df, args.n_llm, args.seed)
    l_tp = l_fp = err = 0
    for x in atk.requests:
        try:
            v, _ = cd.llm_detect_csic(x, args.model, backend=args.backend)
            l_tp += int(v == 'attack')
        except Exception as e:  # noqa: BLE001
            err += 1
            print('  [llm err attack]', type(e).__name__, str(e)[:120], file=sys.stderr)
    for x in ben.requests:
        try:
            v, _ = cd.llm_detect_csic(x, args.model, backend=args.backend)
            l_fp += int(v == 'attack')
        except Exception as e:  # noqa: BLE001
            err += 1
            print('  [llm err benign]', type(e).__name__, str(e)[:120], file=sys.stderr)
    m = metrics(l_tp, len(atk), l_fp, len(ben))
    out['results']['llm'] = dict(attack_caught=[l_tp, len(atk)], benign_fp=[l_fp, len(ben)],
                                 llm_err=err, **m)
    print(f"\n[llm {args.model} / {args.backend}]  recall={l_tp}/{len(atk)} ({m['recall']}) {m['recall_ci']} | "
          f"FP={l_fp}/{len(ben)} ({m['fp_rate']}) {m['fp_ci']} | prec={m['precision']} acc={m['accuracy']} | err={err}")

    run_dir = ROOT / 'research' / 'csic_runs' / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
                                                 + f'-{args.backend}')
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / 'results.json').write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')
    print('\nsaved:', run_dir / 'results.json')


if __name__ == '__main__':
    main()
