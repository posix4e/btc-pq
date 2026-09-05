"""Indefinite hash-commitment holding on stock Core; future recovery is deferred.

This is a holding experiment, not a transaction-signature scheme. A revealed
secret authorizes arbitrary destinations under the existing hashlock rules.
The harness retains the UTXO and never broadcasts a secret-bearing spend.
"""
import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

from .bitcoin import Input, Output, Tx, push
from .core import Core, VERIFIER, verify
from .crypto import ROOT
from .covenant_demo import core_test_helpers
from .shrincs_state import durable_json


def holding_script(commitment):
    if len(commitment)!=32:raise ValueError('32-byte commitment required')
    return b'\xa8'+push(commitment)+b'\x87'


def output_script(commitment):
    return b'\0\x20'+sha256(holding_script(commitment)).digest()


def create_backup(path):
    if path.exists():raise ValueError('backup already exists')
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    secret=secrets.token_bytes(32)
    commitment=sha256(secret).digest()
    durable_json(path,dict(version=1,network='regtest',secret=secret.hex(),commitment=commitment.hex()))
    path.chmod(0o600)
    return commitment


def restore_backup(path,commitment):
    backup=json.loads(path.read_text())
    if backup.get('version')!=1 or backup.get('network')!='regtest':raise ValueError('unsupported backup')
    secret=bytes.fromhex(backup['secret'])
    if len(secret)!=32 or sha256(secret).digest()!=commitment or backup['commitment']!=commitment.hex():
        raise ValueError('backup does not match the funded commitment')
    return secret


def node(binary):
    core_test_helpers()
    from test_framework.segwit_addr import encode_segwit_address
    address=encode_segwit_address('bcrt',0,sha256(b'\x51').digest())
    return Core(str(binary),create_wallet=False,mining_address=address,
                extra_args=('-assumevalid=0','-checklevel=4','-checkblocks=0'))


def write_json(path,data):
    path.write_text(json.dumps(data,indent=2)+'\n')


def prepare(directory,backup,binary='bitcoind'):
    if directory.exists() and any(directory.iterdir()):raise ValueError('empty output directory required')
    directory.mkdir(parents=True,exist_ok=True)
    commitment=create_backup(backup)
    (directory/'blocks').mkdir()
    with node(binary) as core:
        hashes=core.rpc('generatetoaddress',101,core.address)
        coinbase=Tx.parse(core.rpc('getblock',hashes[0],2)['tx'][0]['hex'])
        index=next(i for i,o in enumerate(coinbase.outputs) if o.script==b'\0\x20'+sha256(b'\x51').digest())
        source=coinbase.outputs[index]
        funding=Tx([Input(coinbase.txid,index,witness=[b'\x51'])],
                   [Output(1_000_000,output_script(commitment)),Output(source.value-1_010_000,source.script)])
        core.mine(funding)
        blocks=[]
        for height in range(1,core.rpc('getblockcount')+1):
            path=directory/'blocks'/f'setup-{height:03}.hex'
            path.write_text(core.rpc('getblock',core.rpc('getblockhash',height),0)+'\n')
            blocks.append(str(path.relative_to(directory)))
        tip=core.rpc('getbestblockhash')
        if core.rpc('gettxout',funding.txid,0) is None:raise AssertionError('funding missing')
    (directory/'funding.hex').write_text(funding.serialize().hex()+'\n')
    paths=['funding.hex',*blocks]
    manifest=dict(network='regtest',consensus_changes=[],commitment=commitment.hex(),
                  script_hex=holding_script(commitment).hex(),script_bytes=35,output_script_bytes=34,
                  secret_bytes=32,setup_blocks=blocks,base_tip=tip,funding_txid=funding.txid,
                  files={p:sha256((directory/p).read_bytes()).hexdigest() for p in paths},
                  future_recovery='deferred',transaction_bound_authorization=False)
    write_json(directory/'manifest.json',manifest)
    # A fresh Python process restores the backup and replays funding in a new
    # node. Only public results, never the secret, are returned or published.
    subprocess.run([sys.executable,'-m','btc_pq.holding_demo','replay','--outdir',str(directory),
                    '--backup',str(backup),'--bitcoind',str(binary)],check=True,capture_output=True,text=True)
    return json.loads((directory/'replay.json').read_text())


def replay(directory,backup,binary='bitcoind'):
    manifest=json.loads((directory/'manifest.json').read_text())
    for path,digest in manifest['files'].items():
        if sha256((directory/path).read_bytes()).hexdigest()!=digest:raise ValueError('changed fixture: '+path)
    commitment=bytes.fromhex(manifest['commitment'])
    secret=restore_backup(backup,commitment)
    script=holding_script(commitment)
    funding=Tx.parse((directory/'funding.hex').read_text())
    if funding.outputs[0].script!=output_script(commitment):raise ValueError('wrong funded script')
    # The recipient is an ordinary test output used only in local validation.
    base=Tx([Input(funding.txid,0,witness=[secret,script])],
            [Output(990_000,b'\0\x20'+sha256(b'\x51').digest())])
    rows=[]
    with node(binary) as core, tempfile.TemporaryDirectory() as temp:
        for path in manifest['setup_blocks']:
            if core.rpc('submitblock',(directory/path).read_text().strip()) is not None:
                raise AssertionError('funding replay rejected')
        if core.rpc('getbestblockhash')!=manifest['base_tip']:raise AssertionError('wrong replay tip')
        for name,expected in (('restored_secret',True),('wrong_secret',False),('missing_secret',False),
                              ('schnorr_bytes',False),('wrong_script',False),('extra_item',False),
                              ('copied_secret_changed_recipient',True),('copied_secret_changed_amount',True)):
            tx=deepcopy(base)
            if name=='wrong_secret':tx.inputs[0].witness[0]=bytes([secret[0]^1])+secret[1:]
            if name=='missing_secret':tx.inputs[0].witness=[script]
            if name=='schnorr_bytes':tx.inputs[0].witness=[bytes(64),script]
            if name=='wrong_script':tx.inputs[0].witness[-1]=b'\x51'
            if name=='extra_item':tx.inputs[0].witness.insert(0,b'\x01')
            if name=='copied_secret_changed_recipient':tx.outputs[0].script=b'\0\x14'+bytes(20)
            if name=='copied_secret_changed_amount':tx.outputs[0].value-=1
            path=Path(temp)/'spend.hex';path.write_text(tx.serialize().hex()+'\n')
            checked=verify(path,[directory/'funding.hex'])
            policy=core.rpc('testmempoolaccept',[tx.serialize().hex()])[0]
            if checked['valid']!=expected or policy['allowed']!=expected:raise AssertionError((name,checked,policy))
            # Reports contain public verdicts and sizes, not secret-bearing bytes.
            rows.append(dict(case=name,expected_valid=expected,native_valid=checked['valid'],
                             mempool_allowed=policy['allowed'],transaction_bytes=len(tx.serialize())))
        core.rpc('generatetoaddress',10,core.address)
        remaining=core.rpc('gettxout',funding.txid,0)
        if remaining is None or round(remaining['value']*100_000_000)!=1_000_000:
            raise AssertionError('holding UTXO changed')
        if core.rpc('getrawmempool'):raise AssertionError('secret-bearing transaction entered mempool')
    report=dict(all_expectations_met=True,consensus_changes=[],network='regtest',cases=rows,
                fresh_process_backup_restore=True,fresh_node_funding_replay=True,
                remains_unspent_after_10_more_blocks=True,secret_bearing_spend_broadcast=False,
                future_recovery='deferred',transaction_bound_authorization=False,
                backup_commitment_matches=True,harness_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
                native_verifier_sha256=sha256(VERIFIER.read_bytes()).hexdigest())
    write_json(directory/'replay.json',report)
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('prepare','replay'))
    parser.add_argument('--outdir',type=Path,default=ROOT/'results/holding-demo')
    parser.add_argument('--backup',type=Path,default=ROOT/'.cache/holding-demo/backup.json')
    parser.add_argument('--bitcoind',default='bitcoind')
    args=parser.parse_args()
    result=(prepare if args.action=='prepare' else replay)(args.outdir,args.backup,args.bitcoind)
    print(json.dumps(dict(cases=len(result['cases']),all_expectations_met=result['all_expectations_met'],
                          future_recovery=result['future_recovery'])))
