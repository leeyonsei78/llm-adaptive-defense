#!/bin/bash
# Offline dispatch validation for AutoPenBench (no Ollama needed).
cd /home/lab/labs/autopenbench || exit 1
source .venv/bin/activate
export APB_NO_EVAL=1
export APB_CATEGORY=access_control
export APB_IDX=0
echo "=== probe start $(date -u) ==="
python run_autopenbench_json.py --script scripts/access_control_probe.json 2>&1
echo "=== probe end rc=$? $(date -u) ==="
