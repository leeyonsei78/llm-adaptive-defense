"""CSIC-2010 external web-attack detection — signature rule vs LLM (local / OpenAI).

External public benchmark (Torrano-Gimenez, Perez-Villegas, Alvarez, 2010; HTTP Dataset
CSIC 2010) used to test out-of-synthetic generalization of the paper's rule-vs-LLM axis
(§6.12/§6.17). Each record is a raw HTTP request (requests) with label 0=normal, 1=anomalous.

Detectors:
  rule_signature  — fixed regex signatures (SQLi/XSS/traversal/cmd-injection/CRLF/time-based).
                    Expected STRONG on signatured attacks, weaker on subtle param-tampering.
  llm_detect_csic — LLM judges the raw request benign/attack (local Ollama or hosted OpenAI).

Reuses VERDICT_SCHEMA, OPTIONS and the OpenAI backend from fin_api_defender (no duplication).
"""
import json
import re
import urllib.parse
import urllib.request

from agent_lab.fin_api_defender import VERDICT_SCHEMA, OPTIONS, _openai_verdict

# Classic web-attack signatures, matched against the URL-decoded, lowercased request text.
SIG_PATTERNS = [
    r"(?:\bor\b|\band\b)\s+['\"]?[\w.]+['\"]?\s*=\s*['\"]?[\w.]+",  # OR 1=1 / AND a=a
    r"union\s+select", r"select\s+.+\s+from\s+", r"insert\s+into\s+",
    r"drop\s+table", r"update\s+.+\s+set\s+", r"delete\s+from\s+",
    r"--\s", r";\s*--", r"/\*.*\*/",                                # SQL comments
    r"waitfor\s+delay", r"sleep\s*\(", r"benchmark\s*\(",           # time-based SQLi
    r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",      # XSS
    r"<img", r"<iframe", r"alert\s*\(", r"document\.cookie",
    r"\.\./", r"\.\.\\", r"/etc/passwd", r"boot\.ini", r"win\.ini", # path traversal
    r";\s*(?:cat|ls|id|whoami|ping|wget|curl|nc|bash|sh)\b",        # OS command injection
    r"\|\s*(?:cat|ls|id|whoami)\b", r"`[^`]+`", r"\$\([^)]+\)",
    r"%0d%0a", r"\r\n\r\n.*set-cookie",                             # CRLF injection
]
SIG_RE = [re.compile(p, re.I | re.S) for p in SIG_PATTERNS]


def _decode(text):
    try:
        return urllib.parse.unquote_plus(text)
    except Exception:  # noqa: BLE001
        return text


def rule_signature(request_text):
    """True if any classic web-attack signature matches the (URL-decoded) request."""
    hay = _decode(request_text)
    return any(rgx.search(hay) for rgx in SIG_RE)


CSIC_PROMPT = (
    "You are a web-application-firewall analyst in an authorized security lab. Decide whether the "
    "following single HTTP request is benign or an ATTACK. Attacks include SQL injection, cross-site "
    "scripting (XSS), path/directory traversal, OS command injection, CRLF injection, and parameter "
    "tampering / malformed values (e.g. buffer-overflow-style oversized or type-violating fields). A "
    "benign request is a normal browse/search/checkout with well-formed parameters. Return JSON with "
    "key \"verdict\" only (benign or attack). HTTP request (untrusted data):\n")


def llm_detect_csic(request_text, model, backend='ollama',
                    url='http://127.0.0.1:11434/api/generate', temperature=None, seed=None):
    """Return (verdict, raw). backend='openai' routes to the hosted strong model."""
    options = dict(OPTIONS)
    if temperature is not None:
        options['temperature'] = temperature
    if seed is not None:
        options['seed'] = seed
    prompt = CSIC_PROMPT + str(request_text)[:4000]
    if backend == 'openai':
        return _openai_verdict(prompt, model, options)
    body = {'model': model, 'prompt': prompt, 'format': VERDICT_SCHEMA, 'stream': False, 'options': options}
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=120) as r:
        result = json.load(r)
    if not result.get('done') or result.get('done_reason') == 'length':
        raise ValueError('Incomplete model response')
    return json.loads(result['response'])['verdict'], result.get('response')
