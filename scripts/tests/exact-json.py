#!/usr/bin/env python3
"""Exercise the shipped CLI config read/file-apply paths without rounding JSON tokens."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import os
import subprocess
import tempfile
import threading


CONFIG = b'{"config":{"u64":18446744073709551615,"above_binary64":9007199254740993,"count_min":-170141183460469231731687303715884.105728,"count_max":170141183460469231731687303715884.105727,"quantum":-0.000001},"providers":{}}'
TOKEN = 'exact-json-fixture-token'


def exact(value):
    # Numeric tokens stay distinct from quoted strings and never enter Python binary64.
    return json.loads(value, parse_int=lambda token: ('number', token),
                      parse_float=lambda token: ('number', token))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cli', required=True)
    parser.add_argument('--receipt')
    args = parser.parse_args()
    cli = str(Path(args.cli).resolve())
    received = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, body):
            if self.headers.get('x-admin-token') != TOKEN:
                self.send_error(401)
                return
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path != '/api/v1/admin/config':
                self.send_error(404)
                return
            self.reply(CONFIG)

        def do_POST(self):
            if self.path != '/api/v1/admin/config/apply':
                self.send_error(404)
                return
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size < 1024 * 1024:
                self.send_error(413)
                return
            received.append(self.rfile.read(size))
            self.reply(b'{"applied":true,"config_version":1,"note":"fixture"}')

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    cases = []
    try:
        with tempfile.TemporaryDirectory(prefix='busbar-exact-json-') as temporary:
            root = Path(temporary)
            token = root / 'token'
            token.write_text(TOKEN)
            token.chmod(0o600)
            config = root / 'config.json'
            config.write_bytes(CONFIG)
            config.chmod(0o600)
            base = [cli, '--endpoint', 'http://127.0.0.1:' + str(server.server_port),
                    '--token-file', str(token), '--json']
            env = dict(os.environ)
            env.pop('BUSBAR_ADMIN_TOKEN', None)
            for name, command in [('config-show-exact-tokens', ['config', 'show']),
                                  ('config-file-apply-exact-tokens', ['config', 'apply', str(config)])]:
                try:
                    result = subprocess.run(base + command, capture_output=True,
                                            timeout=30, env=env)
                    assert result.returncode == 0, 'CLI request failed'
                    assert TOKEN.encode() not in result.stdout + result.stderr, 'credential echoed'
                    actual = result.stdout if name == 'config-show-exact-tokens' else received[-1]
                    assert exact(actual) == exact(CONFIG), 'JSON numeric tokens changed or became strings'
                    cases.append({'name': name, 'pass': True})
                except Exception as error:
                    cases.append({'name': name, 'pass': False, 'failure': str(error)})
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
    report = {'scope': 'Actual CLI read/file-apply consumer boundary with controlled HTTP fixture; not core runtime9',
              'cli_binary_sha256': hashlib.sha256(Path(cli).read_bytes()).hexdigest(),
              'cases': cases, 'pass': len(cases) == 2 and all(case['pass'] for case in cases)}
    if args.receipt:
        Path(args.receipt).write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report['pass'] else 1)


if __name__ == '__main__':
    main()
