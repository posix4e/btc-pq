"""Isolated Core node and fail-closed native Script verifier."""
import base64
import json
import socket
import subprocess
import tempfile
import time
import urllib.request
import urllib.error
from pathlib import Path
from .crypto import ROOT

VERIFIER = ROOT/'.cache/native-build/btc-pq-verify'


def verify(spend, parents, verifier=VERIFIER):
    p = subprocess.run([str(verifier), str(spend), *map(str, parents)], capture_output=True, text=True)
    if p.returncode not in (0,1):
        raise RuntimeError(p.stderr.strip() or 'native verifier failed')
    result = json.loads(p.stdout)
    if result['valid'] != (p.returncode == 0):
        raise RuntimeError('inconsistent native verifier exit status')
    return result


class RPCError(RuntimeError):
    def __init__(self, error):
        super().__init__(str(error))
        self.error = error


class Core:
    def __init__(self, bitcoind='bitcoind', create_wallet=True, mining_address=None):
        self.bitcoind = bitcoind
        self.create_wallet = create_wallet
        self.address = mining_address
        self.tmp = None
        self.proc = None
        self.wallet = False
        self.events = []

    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='btc-pq-regtest-')
        self.datadir = Path(self.tmp.name)
        with socket.socket() as s:
            s.bind(('127.0.0.1',0))
            self.port = s.getsockname()[1]
        self.args = [self.bitcoind, f'-datadir={self.datadir}', '-regtest', '-server', '-listen=0',
                     '-networkactive=0', '-dnsseed=0', '-discover=0', '-rpcbind=127.0.0.1',
                     f'-rpcport={self.port}', '-fallbackfee=0.0001', '-printtoconsole=0']
        self.log = (self.datadir/'startup.log').open('w')
        self.proc = subprocess.Popen(self.args, stdout=self.log, stderr=self.log)
        try:
            for _ in range(300):
                if self.proc.poll() is not None:
                    raise RuntimeError((self.datadir/'startup.log').read_text())
                try:
                    cookie = (self.datadir/'regtest/.cookie').read_text().strip()
                    self.auth = base64.b64encode(cookie.encode()).decode()
                    self.info = self.rpc('getnetworkinfo')
                    break
                except (OSError, RPCError):
                    time.sleep(.1)
            else:
                raise RuntimeError('isolated Core startup timed out')
            if self.info['version'] != 310100:
                raise RuntimeError(f"Core 31.1 required, got {self.info['version']}")
            if self.create_wallet:
                self.rpc('createwallet', 'research-public-test-keys')
                self.wallet = True
                self.address = self.rpc('getnewaddress')
            elif not self.address:
                raise ValueError('wallet-free node requires a regtest mining address')
            return self
        except BaseException:
            self.__exit__(None,None,None)
            raise

    def rpc(self, method, *params):
        url = f'http://127.0.0.1:{self.port}/' + ('wallet/research-public-test-keys' if self.wallet else '')
        data = json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=list(params))).encode()
        req = urllib.request.Request(url, data, {'Authorization':'Basic '+self.auth, 'Content-Type':'application/json'})
        try:
            response = urllib.request.urlopen(req, timeout=60)
        except urllib.error.HTTPError as e:
            response = e
        with response:
            result = json.loads(response.read())
        if result.get('error'):
            raise RPCError(result['error'])
        return result['result']

    def mine(self, tx):
        return self.rpc('generateblock', self.address, [tx.serialize().hex()])['hash']

    def __exit__(self, *args):
        if self.proc:
            try:
                self.rpc('stop')
            except (OSError, RPCError, AttributeError):
                self.proc.terminate()
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if hasattr(self,'log'):
            self.log.close()
        if self.tmp:
            self.tmp.cleanup()
