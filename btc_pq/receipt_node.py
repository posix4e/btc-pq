"""Mined funding, exact SHRINCS proofs, and patched regtest-node replay."""
import argparse
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import uuid

from .bitcoin import Input, Output, Tx
from .core import Core, RPCError
from .crypto import ROOT
from .covenant_demo import core_test_helpers, p2mr
from .shrincs_demo import auth_script, signed_message, witness
from .shrincs_state import create, sign
from .shrincs_proof import native, authorizations, TARGET, SERVER, environment
from .receipt_demo import frame, MAGIC
from .receipt_node_build import NODE, BUILD, source_hashes


def save(path, data):
    path.write_text(json.dumps(data,indent=2)+'\n')


def mining_address():
    core_test_helpers()
    from test_framework.segwit_addr import encode_segwit_address
    return encode_segwit_address('bcrt', 0, sha256(b'\x51').digest())


def node(binary=NODE):
    return Core(str(binary),create_wallet=False,mining_address=mining_address(),
                extra_args=('-acceptnonstdtxn=1','-assumevalid=0','-checklevel=4','-checkblocks=0'))


def prepare(directory, stock='bitcoind'):
    if directory.exists() and any(directory.iterdir()):
        raise ValueError('prepare requires an empty fixture directory')
    directory.mkdir(parents=True,exist_ok=True)
    # Signing state stays in the local cache; published fixtures contain only
    # public keys and this valueless regtest payment's signature.
    sender = ROOT/'.cache/receipt-node-signers'/uuid.uuid4().hex
    recipient = ROOT/'.cache/receipt-node-signers'/uuid.uuid4().hex
    sender_key = bytes.fromhex(create(sender)['public_key'])
    recipient_key = bytes.fromhex(create(recipient)['public_key'])
    script = auth_script(sender_key)
    spk, control = p2mr(script)
    destination, _ = p2mr(auth_script(recipient_key))
    with node(stock) as core:
        hashes = core.rpc('generatetoaddress',101,core.address)
        coinbase = Tx.parse(core.rpc('getblock',hashes[0],2)['tx'][0]['hex'])
        source_index = next(i for i,o in enumerate(coinbase.outputs)
                            if o.script == b'\0\x20'+sha256(b'\x51').digest())
        value = coinbase.outputs[source_index].value
        funding = Tx([Input(coinbase.txid,source_index,witness=[b'\x51'])],
                     [Output(1_000_000,spk),Output(value-1_010_000,coinbase.outputs[source_index].script)])
        core.mine(funding)
        (directory/'blocks').mkdir()
        blocks=[]
        for height in range(1,core.rpc('getblockcount')+1):
            path=directory/'blocks'/f'setup-{height:03}.hex'
            path.write_text(core.rpc('getblock',core.rpc('getblockhash',height),0)+'\n')
            blocks.append(str(path.relative_to(directory)))
        tip=core.rpc('getbestblockhash')
    tx=Tx([Input(funding.txid,0)],[Output(800_000,destination)])
    message=signed_message(tx,[funding],0,script)
    signature=bytes.fromhex(sign(sender,message,'receipt-node-payment')['signature'])
    tx.inputs[0].witness=witness(signature,script,control)
    batch=authorizations(tx,[funding],[signature])
    execution=native('execute',batch)
    (directory/'funding.hex').write_text(funding.serialize().hex()+'\n')
    (directory/'direct-spend.hex').write_text(tx.serialize().hex()+'\n')
    save(directory/'batch.json',batch)
    paths=['funding.hex','direct-spend.hex','batch.json',*blocks]
    manifest=dict(network='regtest',consensus_modified=True,setup_blocks=blocks,base_tip=tip,
                  funding_txid=funding.txid,fee_sats=200_000,execution=execution,
                  files={p:sha256((directory/p).read_bytes()).hexdigest() for p in paths})
    save(directory/'manifest.json',manifest)
    return manifest


def load(directory):
    manifest=json.loads((directory/'manifest.json').read_text())
    for path,digest in manifest['files'].items():
        if sha256((directory/path).read_bytes()).hexdigest()!=digest:
            raise ValueError('changed fixture: '+path)
    return manifest


def prove(directory):
    manifest=load(directory)
    batch=json.loads((directory/'batch.json').read_text())
    composite=directory/'composite.receipt.bin'
    compressed=directory/'succinct.receipt.bin'
    if not composite.exists():
        result=native('prove',batch,composite)
        save(directory/'proof.json',result)
    else:
        native('verify',batch,composite)
    if not compressed.exists():
        env=environment();env['RISC0_PROVER']='ipc';env['RISC0_SERVER_PATH']=str(SERVER)
        command=[str(TARGET/'release/btc-pq-receipt-tool'),'compress',str(composite),
                 manifest['execution']['image_id'],manifest['execution']['claims_digest'],str(compressed)]
        result=subprocess.run(command,env=env,capture_output=True,text=True,check=True)
        save(directory/'compression.json',json.loads(result.stdout))
    verification=native('verify',batch,compressed)
    save(directory/'proof-replay.json',dict(result=verification,
         receipts={p.name:sha256(p.read_bytes()).hexdigest() for p in (composite,compressed)}))
    return verification


def restore(core,directory,manifest):
    for path in manifest['setup_blocks']:
        verdict=core.rpc('submitblock',(directory/path).read_text().strip())
        if verdict is not None: raise AssertionError((path,verdict))
    if core.rpc('getbestblockhash')!=manifest['base_tip']:raise AssertionError('different funding tip')


def variants(tx):
    for name in ('recipient','amount','sequence','version','locktime','proof','proof_append',
                 'proof_truncate','missing_proof','version_marker','sentinel','control'):
        changed=deepcopy(tx);w=changed.inputs[0].witness
        if name=='recipient':changed.outputs[0].script=b'\x6a'
        if name=='amount':changed.outputs[0].value-=1
        if name=='sequence':changed.inputs[0].sequence-=1
        if name=='version':changed.version+=1
        if name=='locktime':changed.locktime+=1
        if name=='proof':
            b=bytearray(w[0]);b[len(MAGIC)+64]^=1;w[0]=bytes(b)
        if name=='proof_append':w[0]+=b'\0'
        if name=='proof_truncate':w[0]=w[0][:-1]
        if name=='missing_proof':w.pop(0)
        if name=='version_marker':w[0]=MAGIC[:-1]+b'\x02'+w[0][len(MAGIC):]
        if name=='sentinel':w[1]=b'\x01'
        if name=='control':w[-1]=w[-1][:-1]+bytes([w[-1][-1]^1])
        yield name,changed


def replay(directory):
    manifest=load(directory)
    tx=Tx.parse((directory/'direct-spend.hex').read_text())
    proof=(directory/'succinct.receipt.bin').read_bytes()
    encoded=frame(tx,proof)
    rows=[]
    with node() as core:
        restore(core,directory,manifest)
        info=core.rpc('gettxout',manifest['funding_txid'],0)
        if info is None or round(info['value']*100_000_000)!=1_000_000:raise AssertionError('missing funded UTXO')
        for name,changed in [('valid',encoded),*variants(encoded)]:
            result=core.rpc('testmempoolaccept',[changed.serialize().hex()])[0]
            if result['allowed']!=(name=='valid'):raise AssertionError((name,result))
            rows.append(dict(context='mempool',case=name,result=result))
        accepted=core.rpc('sendrawtransaction',encoded.serialize().hex())
        if accepted!=encoded.txid:raise AssertionError('different accepted transaction')
        # sendrawtransaction warms the full script cache. Raw block candidates
        # bypass the mempool's "same txid already present" shortcut.
        for name,changed in variants(encoded):
            try:
                core.mine(changed)
            except RPCError as error:
                rows.append(dict(context='block_after_cache',case=name,error=error.error))
            else:raise AssertionError('invalid block accepted: '+name)
            if core.rpc('getbestblockhash')!=manifest['base_tip']:raise AssertionError('bad block advanced tip')
        block_hash=core.mine(encoded)
        block_hex=core.rpc('getblock',block_hash,0)
        if core.rpc('gettxout',manifest['funding_txid'],0) is not None:raise AssertionError('input was not spent')
        (directory/'spend-block.hex').write_text(block_hex+'\n')
    with node() as fresh:
        restore(fresh,directory,manifest)
        if fresh.rpc('submitblock',block_hex) is not None:raise AssertionError('fresh replay rejected spend block')
        if fresh.rpc('getbestblockhash')!=block_hash:raise AssertionError('fresh replay tip mismatch')
        output=fresh.rpc('gettxout',encoded.txid,0)
        if output is None or round(output['value']*100_000_000)!=800_000:raise AssertionError('missing recovery output')
    (directory/'proof-spend.hex').write_text(encoded.serialize().hex()+'\n')
    report=dict(all_expectations_met=True,network_node=True,network='regtest',cases=rows,
                mempool_accepted=accepted,mined_block=block_hash,fresh_replay=True,
                transaction=encoded.metrics(),receipt_sha256=sha256(proof).hexdigest(),
                source_sha256=source_hashes(),harness_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
                build_manifest=json.loads((BUILD/'build-manifest.json').read_text()))
    save(directory/'node-replay.json',report)
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('prepare','prove','replay'))
    parser.add_argument('--outdir',type=Path,default=ROOT/'results/shrincs-node')
    parser.add_argument('--stock',default='bitcoind')
    args=parser.parse_args()
    if args.action=='prepare':result=prepare(args.outdir,args.stock)
    elif args.action=='prove':result=prove(args.outdir)
    else:result=replay(args.outdir)
    print(json.dumps(result))
