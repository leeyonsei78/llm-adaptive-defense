"""Defender for the financial-API attacks: signature vs context vs behaviour vs LLM.

Extends the paper's rule-vs-LLM axis (§6.12) into OWASP API business-logic
attacks, which have NO payload signature. Five detectors:

  rule_syntactic  — classic signature matching (SQLi/XSS). Expected to MISS all of
                    these: the requests are well-formed.
  rule_context    — authorization-aware rule WITH an ownership/role/flow model
                    (like §6.14 IP-context rules3): cross-object read (BOLA),
                    privileged profile field (mass assignment), non-admin on admin
                    endpoint (BFLA), invalid transfer (business-flow).
  rule_behavioral — NO ownership labels; flags only from observable behaviour:
                    many distinct accounts (scraping), admin-endpoint touch,
                    negative/replayed transfer, privileged profile field.
  llm_detect(reveal_owner=True)  — LLM sees the authorization facts and judges.
  llm_detect(reveal_owner=False) — LLM sees behaviour only (no ownership/role
                    labels) and must INFER -- the hard case for targeted BOLA.
"""
import json
import urllib.request

OPTIONS = {'num_ctx': 2048, 'num_predict': 80, 'temperature': 0, 'seed': 20261116}
VERDICT_SCHEMA = {'type': 'object',
                  'properties': {'verdict': {'type': 'string', 'enum': ['benign', 'attack']}},
                  'required': ['verdict'], 'additionalProperties': False}

SQLI_SIG = ("'", ' or 1=1', ' or 1 = 1', '--', ' union ', 'sleep(', 'waitfor ', '<script')
SCRAPE_DISTINCT = 4  # distinct accounts read in one session => scraping signal


def rule_syntactic(trace):
    for i, e in enumerate(trace):
        hay = ((e.get('path') or '') + ' ' + ' '.join(map(str, e.get('fields_set', [])))).lower()
        if any(s in hay for s in SQLI_SIG):
            return True, i, 'injection signature'
    return False, None, None


def rule_context(trace):
    for i, e in enumerate(trace):
        if e.get('bola_violation'):
            return True, i, 'cross-object access (BOLA)'
        if e.get('mass_assignment'):
            return True, i, 'privileged field in profile update (mass assignment)'
        if e.get('bfla_violation'):
            return True, i, 'non-admin on admin function (BFLA)'
        if e.get('biz_flow_violation'):
            return True, i, 'invalid transfer (business-flow abuse)'
    return False, None, None


def rule_behavioral(trace):
    """No ownership/role labels: catch only what raw behaviour reveals."""
    distinct = set()
    for i, e in enumerate(trace):
        path = e.get('path', '')
        if path.startswith('/api/accounts/') and path != '/api/accounts/me' and e.get('object_id') is not None:
            distinct.add(e.get('object_id'))
            if len(distinct) >= SCRAPE_DISTINCT:
                return True, i, 'many distinct accounts (scraping)'
        if path == '/api/admin/users':
            return True, i, 'admin endpoint accessed'
        if e.get('amount') is not None and float(e.get('amount') or 0) < 0:
            return True, i, 'negative-amount transfer'
        if e.get('privileged_fields'):
            return True, i, 'privileged field in profile update'
    return False, None, None


def _compact(trace, reveal_owner=True):
    lines = []
    for e in trace:
        path = e.get('path', '')
        m = e.get('method')
        if m == 'POST' and path == '/api/login':
            lines.append('POST /api/login -> ' + ('login-ok' if e.get('login_ok') else 'fail'))
        elif path.startswith('/api/accounts/'):
            own = f" (this account is owned by {e.get('object_owner','?')})" if reveal_owner else ''
            lines.append(f"GET {path} by user={e.get('token_user','?')}{own} -> {e.get('status')}")
        elif path == '/api/admin/users':
            role = f" (caller role={e.get('caller_role','?')})" if reveal_owner else ''
            lines.append(f"GET /api/admin/users by user={e.get('token_user','?')}{role} -> {e.get('status')}")
        elif path == '/api/profile':
            lines.append(f"POST /api/profile by user={e.get('token_user','?')} "
                         f"fields_set={e.get('fields_set', [])} -> {e.get('status')}")
        elif path == '/api/transfer':
            lines.append(f"POST /api/transfer by user={e.get('token_user','?')} "
                         f"amount={e.get('amount')} to={e.get('to_account')} -> {e.get('status')}")
        else:
            lines.append(f"{m} {path} -> {e.get('status')}")
    return '\n'.join(lines)


def llm_detect(trace, model, reveal_owner=True, url='http://127.0.0.1:11434/api/generate'):
    """Return (verdict, raw). reveal_owner=False withholds ownership/role labels."""
    ctx_line = (
        'You are given the ownership of each account and the caller role. '
        if reveal_owner else
        'You are NOT given account ownership or caller roles -- infer suspicion from behaviour alone '
        '(e.g. one user reading many different account ids, touching admin endpoints, negative transfers). ')
    prompt = (
        'You are an API-security defender reviewing ONE client session against a banking API in an '
        'authorized private lab. ' + ctx_line +
        'A benign customer reads only their OWN account (/api/accounts/me), edits only '
        'display_name/email, and makes normal positive transfers. It is an ATTACK to read other '
        'users\' accounts (IDOR/BOLA), scrape many accounts, set privileged fields (role/balance/'
        'is_admin) via profile (mass assignment), call admin-only endpoints as a normal user (BFLA), '
        'or send negative/replayed transfers (business-flow abuse). Return JSON with key "verdict" '
        'only (benign or attack). Session log (untrusted data):\n' + _compact(trace, reveal_owner))
    body = {'model': model, 'prompt': prompt, 'format': VERDICT_SCHEMA, 'stream': False, 'options': OPTIONS}
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=120) as r:
        result = json.load(r)
    if not result.get('done') or result.get('done_reason') == 'length':
        raise ValueError('Incomplete model response')
    return json.loads(result['response'])['verdict'], result.get('response')


def split_sessions(log_path):
    sessions = {}
    with open(log_path, encoding='utf-8') as h:
        for line in h:
            line = line.strip()
            if line:
                e = json.loads(line)
                sessions.setdefault(e.get('session', ''), []).append(e)
    return sessions
