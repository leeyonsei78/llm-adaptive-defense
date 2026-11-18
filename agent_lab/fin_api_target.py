"""Synthetic financial-API target with OWASP API-Top-10 business-logic flaws.

SELF-BUILT, SYNTHETIC, LOOPBACK-ONLY (binds 127.0.0.1; refuses non-loopback).
No real PII, no real money, no real bank. This exists so an attack agent can
generate *real HTTP traffic* exercising API-layer attacks that have NO payload
signature (unlike SQLi) -- the class that recent financial-sector reports flag as
what signature tools and coarse rate limits miss (Thales/Imperva API Threat
Report 2025). The defender then has to *judge authorization context / behaviour*,
not match a string.

Vulnerabilities built in:
  * BOLA / IDOR (OWASP API1): GET /api/accounts/<id> returns ANY account to any
    authenticated caller -- no object-level ownership check.
  * Mass assignment (API3/BOPLA): POST /api/profile applies EVERY posted field,
    including privileged ones (role, balance, is_admin).
  * BFLA (API5): GET /api/admin/users serves admin data to any authenticated
    caller -- no function-level (role) check.
  * Business-flow abuse (API6): POST /api/transfer accepts negative amounts,
    over-balance amounts, and replays (no idempotency) -- no business validation.

Per-request GROUND TRUTH is logged (bola_violation, mass_assignment,
privilege_escalation, bfla_violation, biz_flow_violation, token_user, object_id,
object_owner, distinct_accounts, amount, ...) so detection is scored against
truth -- the requests themselves are well-formed and look normal.

State is per-instance (no module-global mutation) so session types don't leak.

Run:  python agent_lab/fin_api_target.py --port 8710 --log fin.jsonl
"""
import argparse
import copy
import json
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# Synthetic customers only. (user -> record)
USERS = {
    'alice': dict(password='alice-pw', account_id=1001, role='user', balance=5200, email='alice@lab.invalid'),
    'bob':   dict(password='bob-pw',   account_id=1002, role='user', balance=8700, email='bob@lab.invalid'),
    'carol': dict(password='carol-pw', account_id=1003, role='user', balance=300,  email='carol@lab.invalid'),
    'admin': dict(password='admin-pw', account_id=1000, role='admin', balance=0,   email='admin@lab.invalid'),
}
PRIVILEGED_FIELDS = {'role', 'balance', 'is_admin', 'account_id'}  # must NOT be client-settable
EDITABLE_FIELDS = {'display_name', 'email'}                        # the only client-editable fields


class FinTarget:
    def __init__(self, log_path):
        self.log_path = Path(log_path) if log_path else None
        self.users = copy.deepcopy(USERS)                 # per-instance state
        self.owner = {u['account_id']: n for n, u in self.users.items()}
        self.sessions = {}            # token -> username
        self.seen_idemp = set()       # replay detection ground truth
        self._tok = 0

    def log(self, entry):
        entry['ts'] = datetime.now(timezone.utc).isoformat()
        if self.log_path:
            with self.log_path.open('a', encoding='utf-8') as h:
                h.write(json.dumps(entry, ensure_ascii=False) + '\n')

    def login(self, username, password):
        u = self.users.get(username)
        if u and u['password'] == password:
            self._tok += 1
            token = f'tok-{self._tok}'
            self.sessions[token] = username
            return token
        return None


def make_handler(target):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def _send(self, status, body):
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _user(self):
            token = (self.headers.get('Authorization') or '').replace('Bearer ', '').strip()
            return target.sessions.get(token)

        def _rec(self, entry):
            entry.setdefault('path', self.path.split('?', 1)[0])
            entry['client'] = self.client_address[0]
            entry['session'] = self.headers.get('X-Session', '')
            target.log(entry)

        def log_message(self, *a):
            pass

        def do_GET(self):
            path = self.path.split('?', 1)[0]
            if path == '/':
                self._rec(dict(method='GET', status=200))
                return self._send(200, dict(service='synthetic-bank'))
            user = self._user()
            if path == '/api/accounts/me':
                if not user:
                    self._rec(dict(method='GET', status=401)); return self._send(401, dict(error='auth required'))
                acct = target.users[user]['account_id']
                self._rec(dict(method='GET', status=200, token_user=user, object_id=acct,
                               object_owner=user, bola_violation=False))
                return self._send(200, dict(account_id=acct, balance=target.users[user]['balance'], owner=user))
            if path.startswith('/api/accounts/'):           # BOLA (API1)
                if not user:
                    self._rec(dict(method='GET', status=401)); return self._send(401, dict(error='auth required'))
                try:
                    acct = int(path.rsplit('/', 1)[1])
                except ValueError:
                    self._rec(dict(method='GET', status=404, token_user=user)); return self._send(404, dict(error='not found'))
                owner = target.owner.get(acct)
                if owner is None:
                    self._rec(dict(method='GET', status=404, token_user=user, object_id=acct)); return self._send(404, dict(error='no such account'))
                self._rec(dict(method='GET', status=200, token_user=user, object_id=acct,
                               object_owner=owner, bola_violation=owner != user))
                return self._send(200, dict(account_id=acct, balance=target.users[owner]['balance'],
                                            owner=owner, email=target.users[owner]['email']))
            if path == '/api/admin/users':                  # BFLA (API5): no role check
                if not user:
                    self._rec(dict(method='GET', status=401)); return self._send(401, dict(error='auth required'))
                role = target.users[user]['role']
                self._rec(dict(method='GET', status=200, token_user=user, caller_role=role,
                               bfla_violation=role != 'admin'))
                return self._send(200, dict(users=[dict(user=n, account_id=u['account_id'], role=u['role'])
                                                   for n, u in target.users.items()]))
            self._rec(dict(method='GET', status=404)); return self._send(404, dict(error='not found'))

        def do_POST(self):
            path = self.path.split('?', 1)[0]
            length = int(self.headers.get('Content-Length', 0) or 0)
            body = self.rfile.read(length).decode('utf-8', 'replace') if length else ''
            form = {k: v[0] for k, v in urllib.parse.parse_qs(body).items()}
            if path == '/api/login':
                token = target.login(form.get('username', ''), form.get('password', ''))
                self._rec(dict(method='POST', status=200, login_ok=bool(token)))
                return self._send(200, dict(authenticated=bool(token), token=token))
            user = self._user()
            if path == '/api/profile':                      # Mass assignment (API3)
                if not user:
                    self._rec(dict(method='POST', status=401)); return self._send(401, dict(error='auth required'))
                posted = set(form.keys())
                privileged = sorted(posted & PRIVILEGED_FIELDS)
                for k, v in form.items():                   # the flaw: no field allowlist
                    target.users[user][k] = v
                esc = (form.get('role') == 'admin') or (str(form.get('is_admin', '')).lower() in ('1', 'true', 'yes'))
                self._rec(dict(method='POST', status=200, token_user=user, fields_set=sorted(posted),
                               privileged_fields=privileged, mass_assignment=bool(privileged),
                               privilege_escalation=bool(esc)))
                return self._send(200, dict(updated=sorted(posted), role=target.users[user].get('role'),
                                            balance=target.users[user].get('balance')))
            if path == '/api/transfer':                     # Business-flow abuse (API6)
                if not user:
                    self._rec(dict(method='POST', status=401)); return self._send(401, dict(error='auth required'))
                try:
                    amount = float(form.get('amount', '0'))
                except ValueError:
                    amount = 0.0
                idemp = form.get('idempotency_key', '')
                bal = float(target.users[user].get('balance', 0))
                negative = amount < 0
                over = amount > bal
                replay = bool(idemp) and idemp in target.seen_idemp
                if idemp:
                    target.seen_idemp.add(idemp)
                violation = negative or over or replay      # no business validation -> served anyway
                self._rec(dict(method='POST', status=200, token_user=user, amount=amount,
                               to_account=form.get('to_account', ''), negative=negative,
                               over_balance=over, replay=replay, biz_flow_violation=violation))
                return self._send(200, dict(ok=True, amount=amount, to=form.get('to_account', '')))
            self._rec(dict(method='POST', status=404)); return self._send(404, dict(error='not found'))

    return Handler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=8710)
    ap.add_argument('--log', default='')
    args = ap.parse_args()
    if args.host not in ('127.0.0.1', 'localhost', '::1'):
        raise SystemExit('refusing non-loopback bind: ' + args.host)
    target = FinTarget(args.log)
    httpd = ThreadingHTTPServer((args.host, args.port), make_handler(target))
    print(f'fin-api target on http://{args.host}:{args.port}  log={args.log or "(none)"}', flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
