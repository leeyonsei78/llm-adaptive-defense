"""Smoke tests for the financial-API slice (no model needed)."""
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_lab import fin_api_target as tgt
from agent_lab import fin_api_attacker as atk
from agent_lab import fin_api_defender as dfn


def run():
    tmp = Path(__file__).resolve().parent / '_test_fin.jsonl'
    if tmp.exists():
        tmp.unlink()
    target = tgt.FinTarget(str(tmp))
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), tgt.make_handler(target))
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.2)
    base = f'http://127.0.0.1:{port}'
    n = 0

    assert atk.benign_session(base, 'benign-0')['token']; n += 1
    assert atk.bola_session(base, 'bola-0')['bola_success']; n += 1
    assert atk.scraping_bola_session(base, 'scraping_bola-0')['scraped'] >= 3; n += 1
    assert atk.mass_assignment_session(base, 'mass_assignment-0')['escalated']; n += 1
    assert atk.bfla_session(base, 'bfla-0')['admin_access']; n += 1
    atk.transfer_abuse_session(base, 'transfer_abuse-0'); n += 1
    httpd.shutdown()
    s = dfn.split_sessions(str(tmp))

    # syntactic rule catches NONE of these (no signature)
    for t in ('bola', 'scraping_bola', 'mass_assignment', 'bfla', 'transfer_abuse'):
        assert dfn.rule_syntactic(s[t + '-0'])[0] is False, t; n += 1
    # context rule catches all attacks, not benign
    for t in ('bola', 'scraping_bola', 'mass_assignment', 'bfla', 'transfer_abuse'):
        assert dfn.rule_context(s[t + '-0'])[0] is True, t; n += 1
    assert dfn.rule_context(s['benign-0'])[0] is False; n += 1
    # behavioral rule (no ownership): catches scraping/mass/bfla/transfer, MISSES targeted bola, not benign
    assert dfn.rule_behavioral(s['scraping_bola-0'])[0] is True; n += 1
    assert dfn.rule_behavioral(s['mass_assignment-0'])[0] is True; n += 1
    assert dfn.rule_behavioral(s['bfla-0'])[0] is True; n += 1
    assert dfn.rule_behavioral(s['transfer_abuse-0'])[0] is True; n += 1
    assert dfn.rule_behavioral(s['bola-0'])[0] is False, 'targeted BOLA should evade behavioural rule'; n += 1
    assert dfn.rule_behavioral(s['benign-0'])[0] is False; n += 1

    tmp.unlink()
    print(f'ALL FIN-API TESTS PASSED ({n} assertions)')


if __name__ == '__main__':
    run()
