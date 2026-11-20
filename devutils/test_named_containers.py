#!/usr/bin/env python3
# Copyright (c) 2026 The Helium Authors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the named-tab login check against a built desktop Helium executable."""

import argparse
from contextlib import contextmanager
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import queue
import secrets
import subprocess
import tempfile
import threading
import time
from urllib.request import urlopen


class LoginSite(BaseHTTPRequestHandler):
    """A single origin with dummy accounts and server-side sessions."""

    def do_GET(self):
        action, _, label = self.path.lstrip('/').partition('/')
        if action == 'spawn' and label in ('opener', 'noopener'):
            features = 'noopener' if label == 'noopener' else ''
            body = (f'<script>window.open("/who/{label}", "_blank", '
                    f'"{features}");</script>').encode('ascii')
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if action == 'login' and label in self.server.tokens:
            token = self.server.tokens[label]
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header('Set-Cookie',
                             f'session={token}; HttpOnly; SameSite=Lax; Path=/')
            self.send_header('Location', f'/who/{label}-after-login')
        elif action == 'who':
            cookies = SimpleCookie(self.headers.get('Cookie', ''))
            session = cookies.get('session')
            account = next((name for name, token in self.server.tokens.items()
                            if session and token == session.value), 'signed out')
            self.server.visits.put((label, account))
            self.send_response(HTTPStatus.OK)
        else:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def log_message(self, *_args):
        pass


@contextmanager
def running_browser(binary, directory, *, enabled):
    profile = Path(directory).resolve()
    common = [str(binary), f'--user-data-dir={profile}', '--no-first-run',
              '--no-default-browser-check', '--use-mock-keychain', '--disable-popup-blocking']
    with (profile / 'browser.log').open('w+') as log:
        features = ['--enable-features=HeliumNamedContainers'] if enabled else []
        process = subprocess.Popen(
            common + features + ['--remote-debugging-port=0', 'about:blank'],
            stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 40
            port_file = profile / 'DevToolsActivePort'
            while not port_file.exists() and time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                time.sleep(0.1)
            if not port_file.exists():
                raise RuntimeError('Helium did not start with the fresh profile')
            port = int(port_file.read_text().splitlines()[0])
            while time.monotonic() < deadline:
                with urlopen(f'http://127.0.0.1:{port}/json/list', timeout=5) as response:
                    if any(tab['url'] == 'about:blank' for tab in json.load(response)):
                        break
                time.sleep(0.1)
            else:
                raise RuntimeError('Initial browser tab did not finish opening')
            yield common, port
        except Exception:
            log.seek(0)
            print(log.read()[-3000:])
            raise
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def run(binary):
    with ThreadingHTTPServer(('127.0.0.1', 0), LoginSite) as site:
        site.tokens = {name: secrets.token_hex(20) for name in ('alice', 'bob', 'casey')}
        site.visits = queue.Queue()
        thread = threading.Thread(target=site.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix='helium-containers-') as tmp:
                with running_browser(binary, tmp, enabled=True) as (command, port):
                    origin = f'http://127.0.0.1:{site.server_port}'
                    cases = [
                        ('Work', 'login/alice', 'alice-after-login', 'alice'),
                        ('Work', 'who/work-2', 'work-2', 'alice'),
                        ('Personal', 'who/personal-1', 'personal-1', 'signed out'),
                        (None, 'who/ordinary-1', 'ordinary-1', 'signed out'),
                        ('Personal', 'login/bob', 'bob-after-login', 'bob'),
                        ('Work', 'who/work-3', 'work-3', 'alice'),
                        ('Personal', 'who/personal-2', 'personal-2', 'bob'),
                        (None, 'who/ordinary-2', 'ordinary-2', 'signed out'),
                        ('Work', 'spawn/opener', 'opener', 'alice'),
                        ('Personal', 'spawn/noopener', 'noopener', 'bob'),
                        ('QA.v2/team', 'who/custom-1', 'custom-1', 'signed out'),
                        ('QA.v2/team', 'login/casey', 'casey-after-login', 'casey'),
                        ('QA.v2/team', 'who/custom-2', 'custom-2', 'casey'),
                    ]
                    for container, path, label, expected in cases:
                        args = [f'--container={container}'] if container else []
                        subprocess.run(command + args + [f'{origin}/{path}'],
                                       check=True, timeout=25,
                                       stdout=subprocess.DEVNULL, cwd=tmp)
                        try:
                            visit = site.visits.get(timeout=20)
                        except queue.Empty as error:
                            raise AssertionError(f'No request for {label}') from error
                        if visit != (label, expected):
                            raise AssertionError(f'{label}: expected {expected}, got {visit}')
                        print(f'{label}: {expected}', flush=True)

                    # Confirm the probes were separate, concurrently open tabs
                    # in this browser, rather than sequential loads in one tab.
                    expected_tabs = {f'{origin}/who/{label}' for _, _, label, _ in cases}
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        with urlopen(f'http://127.0.0.1:{port}/json/list', timeout=5) as response:
                            tabs = json.load(response)
                        targets = {tab['url'] for tab in tabs if tab['type'] == 'page'}
                        if expected_tabs <= targets:
                            break
                        time.sleep(0.1)
                    else:
                        raise AssertionError(f'Missing live tabs: {expected_tabs - targets}')
            # A second, fresh profile checks the shipped default. An explicit
            # container request must not silently sign in through the ordinary jar.
            with tempfile.TemporaryDirectory(prefix='helium-flag-off-') as tmp:
                with running_browser(binary, tmp, enabled=False) as (command, _):
                    for args in (['--container=Work', f'{origin}/who/should-not-load'],
                                 [f'{origin}/who/flag-off-ordinary']):
                        subprocess.run(command + args, check=True, timeout=25,
                                       stdout=subprocess.DEVNULL, cwd=tmp)
                    try:
                        visit = site.visits.get(timeout=20)
                    except queue.Empty as error:
                        raise AssertionError('No ordinary request with flag off') from error
                    if visit != ('flag-off-ordinary', 'signed out'):
                        raise AssertionError(f'Flag-off container request reached the site: {visit}')
                    print('flag off: ordinary tab loaded, named URL withheld', flush=True)
        finally:
            site.shutdown()
            thread.join()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path, help='path to the Helium browser executable')
    run(parser.parse_args().binary.resolve(strict=True))
