"""Re-judge a saved AutoPenBench trajectory with a DIFFERENT local judge model,
to test whether finding B (the local-LLM evaluator fabricates milestone success)
is model-dependent (paper §6.19 / §6.11 model-dependence, applied to the judge).

It replays the SAME per-step milestone evaluation the runner did (LiteEvaluator),
but with the model given by JUDGE_MODEL, over the steps parsed from the saved log,
then compares the new judge's claims to the deterministic ground truth.

Run INSIDE the guest venv, from the autopenbench root:
  OPENAI_BASE_URL=http://10.0.2.2:11500/v1 JUDGE_MODEL=qwen2.5-coder:14b \
    python rejudge_trajectory.py research/autopenbench_runs/<trajectory>.log
(the runner + score_trajectory modules must be importable: run from the dir that
 holds run_autopenbench_json.py, or set PYTHONPATH to it.)
"""
import os
import sys

os.environ.setdefault('OPENAI_BASE_URL', 'http://10.0.2.2:11500/v1')
os.environ.setdefault('OPENAI_API_KEY', 'ollama-local')

JUDGE_MODEL = os.environ.get('JUDGE_MODEL', 'qwen2.5-coder:14b')
LEVEL = os.environ.get('APB_LEVEL', 'in-vitro')
CATEGORY = os.environ.get('APB_CATEGORY', 'access_control')
IDX = int(os.environ.get('APB_IDX', '0'))

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from openai import OpenAI  # noqa: E402
from autopenbench.utils import load_milestones  # noqa: E402
from run_autopenbench_json import LiteEvaluator  # noqa: E402
from score_trajectory import parse, ground_truth, required_cap  # noqa: E402


def fp_counts(names, sig):
    tp = sum(1 for n in names if sig.get(required_cap(n), False))
    return len(names), tp, len(names) - tp


def main():
    if len(sys.argv) < 2:
        print('usage: rejudge_trajectory.py <trajectory.log>')
        return 2
    log = sys.argv[1]
    steps = parse(log)
    sig, _ = ground_truth(steps)

    init_cmd = load_milestones('command', LEVEL, CATEGORY, IDX)
    init_stg = load_milestones('stage', LEVEL, CATEGORY, IDX)
    client = OpenAI()
    ev = LiteEvaluator(client, JUDGE_MODEL, list(init_cmd), list(init_stg), no_llm=False)

    print(f'=== re-judge: {log}', flush=True)
    print(f'    judge model = {JUDGE_MODEL}  base = {os.environ["OPENAI_BASE_URL"]}', flush=True)
    print(f'    steps = {len(steps)}  command_ms = {len(init_cmd)}  stage_ms = {len(init_stg)}', flush=True)

    for s in steps:
        step_str = f"Action:{s['args']}\nObservation: {s['obs']}"
        ev.evaluate_step(step_str)

    claimed_cmd = [m for m in init_cmd if m not in ev.command_ms]
    claimed_stg = [m for m in init_stg if m not in ev.stage_ms]
    c_claim, c_tp, c_fp = fp_counts(claimed_cmd, sig)
    s_claim, s_tp, s_fp = fp_counts(claimed_stg, sig)

    print('\n-- ground-truth signals --', flush=True)
    for k, v in sig.items():
        print(f'   {k:16} = {v}', flush=True)
    print(f'\n-- judge {JUDGE_MODEL} vs ground truth --', flush=True)
    pc = f'{100*c_fp/c_claim:.0f}%' if c_claim else 'n/a'
    ps = f'{100*s_fp/s_claim:.0f}%' if s_claim else 'n/a'
    print(f'   COMMAND: claimed {c_claim}, gt-true {c_tp}, FALSE POSITIVES {c_fp} ({pc})', flush=True)
    print(f'   STAGE  : claimed {s_claim}, gt-true {s_tp}, FALSE POSITIVES {s_fp} ({ps})', flush=True)
    print('\n-- claimed command milestones --', flush=True)
    for n in claimed_cmd:
        tag = 'OK' if sig.get(required_cap(n), False) else 'FP'
        print(f'   [{tag}] (needs {required_cap(n)}) {n}', flush=True)
    print('-- claimed stage milestones --', flush=True)
    for n in claimed_stg:
        tag = 'OK' if sig.get(required_cap(n), False) else 'FP'
        print(f'   [{tag}] (needs {required_cap(n)}) {n}', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
