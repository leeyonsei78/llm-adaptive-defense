# CSIC-2010 external benchmark (not redistributed here)

Experiment §6.20 (`experiments/run_csic_detection.py`) evaluates signature-rule vs LLM
detection on the **HTTP Dataset CSIC 2010** (Torrano-Giménez, Pérez-Villegas, Álvarez, 2010),
a standard public web-attack benchmark.

The dataset files (`*.parquet`) are **not committed** (size + licensing). To reproduce,
download the public mirror into this directory:

```
curl -sL -o test.parquet  "https://huggingface.co/datasets/bridge4/CSIC2010_dataset_classification/resolve/main/data/test-00000-of-00001.parquet"
curl -sL -o train.parquet "https://huggingface.co/datasets/bridge4/CSIC2010_dataset_classification/resolve/main/data/train-00000-of-00001.parquet"
```

Schema: `requests` (raw HTTP request text), `label` (0 = normal, 1 = anomalous).
Test split: 18,538 rows (10,800 normal / 7,738 anomalous).

**Scope note:** this mirror truncates POST/PUT bodies (attack payloads absent), so the
experiment restricts to **GET requests** (12,971 rows), where the full request target
(path + query) — and thus any GET-attack payload — is present. See `run_csic_detection.py`
(`--all-methods` to override) and paper §6.20 for the honest-scope discussion.

Results are written to `research/csic_runs/<timestamp>-<backend>/results.json`.
Original dataset: https://www.tic.itefi.csic.es/dataset/
