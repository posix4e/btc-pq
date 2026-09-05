"""Modified-consensus hash-to-signature experiment. Isolated regtest only.

This is a toy hash predicate, NOT QSB's RIPEMD160-to-DER construction. Stock
Core must reject every experimental spend. All preimages are public test data;
the frozen-disclosure experiment explicitly restricts which can be consumed.
"""
from copy import deepcopy
from hashlib import sha256
from itertools import combinations
from math import comb
from pathlib import Path
import json
import platform
import subprocess
import tempfile
import time

from .bitcoin import Tx, Input, Output, num, instructions, legacy_sighash
from .core import Core, RPCError, verify, VERIFIER as STOCK_VERIFIER
from .crypto import ROOT, ec, recover, encode, secret
from .experiments import write_tx
from .phase2 import Instance, Parameters, Search, hash160, timing
from . import toy_build

DOMAIN = b'BTC-PQ-TOY-H2S-v1'
S_DOMAIN = b'BTC-PQ-TOY-S-v1'


def toy_signature(key, bits):
    """Independent Python definition of the experimental opcode."""
    if not 1 <= bits <= 24 or len(key) != 33 or key[0] not in (2,3):
        return None
    h = sha256(DOMAIN + bytes([bits]) + key).digest()
    if int.from_bytes(h,'big') >> (256-bits):
        return None
    s = 1 + int.from_bytes(sha256(S_DOMAIN+h).digest()[:16],'big')
    return ec.encode_der_sig(2,s,1)


class ToyInstance(Instance):
    def __init__(self,bits,entries,selections):
        self.bits = bits
        if not 1 <= bits <= 24:
            raise ValueError('toy work bits must be 1..24')
        super().__init__(Parameters(entries,selections,'hash-to-der'))

    def compile(self):
        self.preimages = [secret(f'toy/b{self.bits}/hors/{i}') for i in range(self.params.entries)]
        self.commitments = list(map(hash160,self.preimages))
        script = super().compile()
        pieces = []; replaced = 0
        for a,op,_,b in instructions(script):
            if op == 0xa6:
                pieces.append(num(self.bits)+b'\x7e'); replaced += 1
            else:
                pieces.append(script[a:b])
        if replaced != 2:
            raise AssertionError('expected pinning and one digest hash opcode')
        return b''.join(pieces)

    def proof_key(self,tx,digest):
        key = self.key(digest)
        sig = toy_signature(key,self.bits) if key is not None else None
        if sig is None:
            raise ValueError('attempt to assemble a key that fails the toy hash target')
        s = int.from_bytes(sig[7:-1],'big')  # r has exactly one byte, r=2
        z = legacy_sighash(tx,1,self.script,sig,1)
        q = recover(2,s,z,0)
        if q is None:
            raise ValueError('toy puzzle public-key recovery failed')
        return encode(q)


def native(request):
    start = time.perf_counter()
    limit = float(request.get('max_seconds',30))
    proc = subprocess.run([str(toy_build.SEARCH)], input=json.dumps(request),
                          capture_output=True,text=True,timeout=limit+30)
    if proc.returncode:
        raise RuntimeError(proc.stderr.strip() or 'native toy search failed')
    result = json.loads(proc.stdout)
    result['subprocess_wall_seconds'] = time.perf_counter()-start
    return result


def authorization_bytes(tx,selections):
    """Exact HORS preimage/index pushes, excluding public keys and proofs."""
    script=tx.inputs[1].script
    ops=list(instructions(script))
    start=2+selections
    return script[ops[start][0]:ops[start+2*selections-1][3]]


def check_build():
    manifest=json.loads((toy_build.BUILD/'build-manifest.json').read_text())
    for path,expected in {**manifest['source_inputs'],**manifest['binaries']}.items():
        if sha256((ROOT/path).read_bytes()).hexdigest()!=expected:
            raise RuntimeError(f'toy build is stale ({path}); rebuild with --build')
    return manifest


def differential_and_benchmark():
    values = [0,1,ec.N-1,ec.N,ec.N+1,2**256-1]
    digests = [v.to_bytes(32,'big') for v in values] + [secret(f'toy/vector/{i}') for i in range(48)]
    data = native(dict(mode='vectors',bits=4,digests=[d.hex() for d in digests]))
    for row,digest in zip(data['vectors'],digests,strict=True):
        q = recover(ec.G[0],1,digest,0)
        expected = encode(q).hex() if q else ''
        if row['key_hex'] != expected or row['general_recovery_key_hex'] != expected:
            raise AssertionError('native scalar shortcut, native general recovery, and Python recovery disagree')
        sig = toy_signature(bytes.fromhex(expected),4)
        if row['passes'] != (sig is not None) or row['signature_hex'] != (sig.hex() if sig else ''):
            raise AssertionError('native/Python toy predicate mismatch')
    if not any(v['passes'] for v in data['vectors']):
        raise AssertionError('differential vectors must exercise a successful toy predicate')
    data['all_matched'] = True
    return dict(differential=data,benchmark=native(dict(mode='benchmark',bits=20,max_candidates=10_000,max_seconds=30)))


def search(instance,tx,mode,max_candidates,max_seconds,counter=0,frozen=None):
    template = Search(instance,tx,max_candidates,time.perf_counter()+max_seconds)
    request = dict(mode=mode,bits=instance.bits,max_candidates=max_candidates,max_seconds=max_seconds,
                   counter=counter,sequence=tx.inputs[1].sequence,selections=instance.params.selections,
                   prefix_hex=template.prefix.hex(),tail_hex=template.tail.hex(),code_hex=template.code.hex(),
                   spans=[list(template.spans[i]) for i in range(instance.params.entries)])
    if frozen is not None:
        request['frozen_indices'] = list(frozen)
    result = native(request)
    if result['found']:
        tx.inputs[1].sequence = result['sequence']
        hits = [(result['hit'], result.get('selected_indices') if mode=='subset' else None)]
        if mode=='frozen':
            hits.append((result['digest_hit'],frozen))
        for hit,subset in hits:
            digest = bytes.fromhex(hit['digest_hex'])
            if digest != instance.digest(tx,subset) or instance.key(digest).hex() != hit['key_hex']:
                raise AssertionError('native search hit does not match Python sighash/key reference')
            if toy_signature(bytes.fromhex(hit['key_hex']),instance.bits).hex() != hit['signature_hex']:
                raise AssertionError('native search hit does not match Python toy signature')
    return result


def node_guard():
    with tempfile.TemporaryDirectory(prefix='btc-pq-toy-chain-guard-') as directory:
        proc = subprocess.run([str(toy_build.NODE),f'-datadir={directory}','-chain=signet',
                               '-networkactive=0','-listen=0','-dnsseed=0','-printtoconsole=0'],
                              capture_output=True,text=True,timeout=20)
    if proc.returncode == 0 or 'BTC-PQ TOY CONSENSUS BUILD: regtest only' not in proc.stderr:
        raise AssertionError('experimental node did not reject non-regtest startup')
    return dict(chain='signet',started=False,exit_code=proc.returncode,error=proc.stderr.strip())


DIMENSIONS = {4:(16,3),6:(24,3),8:(24,3),12:(32,4),16:(40,5),20:(64,5)}


def run(outdir,levels=(8,12,16,20),reuse_bits=(4,6),reuse_trials=3,
        bitcoind='bitcoind',max_candidates=32_000_000,max_seconds=300):
    levels, reuse_bits = tuple(levels), tuple(reuse_bits)
    if not levels or set(levels+reuse_bits)-DIMENSIONS.keys() or len(set(levels)) != len(levels):
        raise ValueError('supported levels: 4,6,8,12,16,20; levels must be nonempty and unique')
    if len(set(reuse_bits)) != len(reuse_bits) or reuse_trials < 1 or max_candidates < 1 or max_seconds <= 0:
        raise ValueError('invalid reuse or search parameters')
    if any(b>8 for b in reuse_bits):
        raise ValueError('frozen-disclosure experiments are deliberately limited to at most 8 bits')
    outdir = Path(outdir)
    if outdir.exists() and any(outdir.iterdir()):
        raise ValueError('choose a new, empty output directory')
    outdir.mkdir(parents=True,exist_ok=True)
    blocks = outdir/'blocks'; blocks.mkdir()
    start_all = time.perf_counter()
    result = dict(schema_version=1,consensus_modified=True,qsb_exact_reproduction=False,
        full_strength_demonstration=False,secure_candidate_demonstrated=False,
        experiment='toy_hash_to_signature_with_frozen_disclosure_measurements',status='in_progress',
        scope='isolated regtest; valueless coins; all witness data public',
        predicate=dict(name='BTC-PQ-TOY-H2S-v1',opcode_hex='7e',
            stock_behavior='disabled opcode; NOT OP_CAT support',
            input='compressed public key Q and funded integer b, 1 <= b <= 24',
            hash='h = SHA256(ASCII("BTC-PQ-TOY-H2S-v1") || uint8(b) || Q)',
            gate='first b most significant bits of h must be zero',
            signature='DER(r=2, s=1+BE(SHA256(ASCII("BTC-PQ-TOY-S-v1") || h)[0:16])) || 01',
            signature_sighash='SIGHASH_ALL',digest_rounds=1,
            failure='Script failure; no relaxed DER parsing or ECDSA verification'),
        consensus_changes=['Experimental verification flag enables opcode 0x7e in legacy BASE scripts on regtest.',
                           'Experimental daemon refuses non-regtest startup.'],
        relay_policy_changes=[],limits=dict(max_script_bytes=10000,max_counted_opcodes=201),
        reductions=dict(published_hash_to_der_replaced=True,published_work_bits_approx=46.4,
                        published_digest_rounds=2,experimental_digest_rounds=1,bonus_selections=0,
                        searched_key_branch='compressed R=G only',all_preimages_public=True),
        parameters=dict(levels=list(levels),reuse_bits=list(reuse_bits),reuse_trials=reuse_trials,
                        max_candidates_per_search=max_candidates,max_seconds_per_search=max_seconds),
        environment=dict(platform=platform.platform(),python=platform.python_version(),cpu=platform.machine()),
        build=check_build(),
        instances=[],lifecycles=[],frozen_disclosure=[],cases=[],setup_blocks=[])
    result['source_sha256']={str(p.relative_to(ROOT)):sha256(p.read_bytes()).hexdigest()
                            for p in [Path(__file__),ROOT/'btc_pq/toy_build.py',ROOT/'btc_pq/phase2.py',
                                      ROOT/'btc_pq/bitcoin.py',ROOT/'btc_pq/core.py',ROOT/'btc_pq/crypto.py',ROOT/'btc_pq/cli.py']}
    result['stock_verifier_sha256']=sha256(STOCK_VERIFIER.read_bytes()).hexdigest()

    def save(final=False):
        result['total_wall_seconds'] = time.perf_counter()-start_all
        (outdir/('results.json' if final else 'partial-results.json')).write_text(json.dumps(result,indent=2)+'\n')

    try:
        result['non_regtest_guard'] = node_guard()
        result['native_validation'] = differential_and_benchmark()
        rate=result['native_validation']['benchmark']['measurement']['candidates_per_second']
        print(f'toy: native benchmark {rate:,.0f} candidates/s; Python/general-recovery cross-check passed',flush=True)
        instances = {b:ToyInstance(b,*DIMENSIONS[b]) for b in sorted(set(levels+reuse_bits))}
        for b,instance in instances.items():
            path=outdir/f'b{b}-public-tables.json'
            path.write_text(json.dumps([dict(index=i,preimage_hex=pre.hex(),commitment_hex=instance.commitments[i].hex(),
                                            dummy_hex=instance.dummies[i].hex(),dummy_key_hex=instance.dummy_keys[i].hex())
                                       for i,pre in enumerate(instance.preimages)],indent=2)+'\n')
            (outdir/f'b{b}-locking-script.hex').write_text(instance.script.hex()+'\n')
            result['instances'].append(dict(bits=b,table_entries=instance.params.entries,selections=instance.params.selections,
                subset_space=comb(instance.params.entries,instance.params.selections),script=instance.metrics,
                fixed_signature_hex=instance.fixed.hex(),tables_file=path.name))
        with Core(bitcoind) as stock:
            before=time.perf_counter()
            stock.rpc('generatetoaddress',101,stock.address)
            utxo=sorted(stock.rpc('listunspent',100),key=lambda x:x['txid'])[0]
            outputs=[]; indices={}
            for b,instance in instances.items():
                indices[b]=len(outputs); outputs.extend([Output(1_000_000,b'\x51'),Output(1_000_000,instance.script)])
            change=bytes.fromhex(stock.rpc('getaddressinfo',stock.address)['scriptPubKey'])
            outputs.append(Output(round(utxo['amount']*100_000_000)-sum(o.value for o in outputs)-10_000,change))
            funding=Tx([Input(utxo['txid'],utxo['vout'])],outputs)
            signed=stock.rpc('signrawtransactionwithwallet',funding.serialize().hex())
            if not signed['complete']: raise RuntimeError('funding incomplete')
            funding=Tx.parse(signed['hex']); funding_path=write_tx(outdir/'funding.hex',funding)
            parent=outdir/'funding-parent.hex'; parent.write_text(stock.rpc('gettransaction',utxo['txid'])['hex']+'\n')
            funding_native=verify(funding_path,[parent])
            if not funding_native['valid']: raise AssertionError('stock native funding failure')
            h=stock.mine(funding)
            result['funding']=dict(**timing(before),file=funding_path.name,transaction=funding.metrics(),
                stock_native=funding_native,stock_blockhash=h,output_indices=indices,
                timing_scope='101 maturity blocks, signing, stock native verification and funding block')
            result['base_tip']=stock.rpc('getbestblockhash'); result['mining_address']=stock.address
            for height in range(1,stock.rpc('getblockcount')+1):
                h=stock.rpc('getblockhash',height); path=blocks/f'setup-{height:03}.hex'
                path.write_text(stock.rpc('getblock',h,0)+'\n'); result['setup_blocks'].append(str(path.relative_to(outdir)))
            with Core(str(toy_build.NODE),create_wallet=False,mining_address=stock.address) as toy:
                for path in result['setup_blocks']:
                    if toy.rpc('submitblock',(outdir/path).read_text().strip()) is not None:
                        raise AssertionError('experimental node rejected stock funding chain')
                result['nodes']={}
                for name,node in [('stock',stock),('toy',toy)]:
                    info=node.rpc('getnetworkinfo'); chain=node.rpc('getblockchaininfo')['chain']
                    if chain!='regtest' or info['networkactive']: raise AssertionError('node isolation failed')
                    result['nodes'][name]=dict(version=info['version'],chain=chain,networkactive=False,
                                              subversion=info['subversion'],temporary_datadir=True)

                def base(bits,value):
                    i=indices[bits]
                    return Tx([Input(funding.txid,i),Input(funding.txid,i+1,sequence=0x80000000)], [Output(value,b'\x51')])

                def validate(name,tx,expected):
                    if toy.rpc('getbestblockhash')!=result['base_tip'] or stock.rpc('getbestblockhash')!=result['base_tip']:
                        raise AssertionError('validation must start at funded tip')
                    path=write_tx(outdir/f'{name}.hex',tx)
                    row=dict(name=name,file=path.name,transaction=tx.metrics(),expected_toy_acceptance=expected)
                    before=time.perf_counter(); row['toy_native']=verify(path,[funding_path]*2,toy_build.VERIFIER)
                    row['toy_native_timing']=timing(before)
                    before=time.perf_counter(); row['stock_native']=verify(path,[funding_path]*2)
                    row['stock_native_timing']=timing(before)
                    before=time.perf_counter()
                    try:
                        h=toy.mine(tx); row['toy_block_accepted']=True
                    except RPCError as error:
                        row.update(toy_block_accepted=False,toy_block_error=error.error)
                    row['toy_block_timing']=timing(before)
                    if row['toy_block_accepted']:
                        if tx.txid not in toy.rpc('getblock',h,1)['tx']: raise AssertionError('spend absent from accepted block')
                        path=blocks/f'{name}.hex'; path.write_text(toy.rpc('getblock',h,0)+'\n')
                        row.update(blockhash=h,block_file=str(path.relative_to(outdir)))
                        toy.rpc('invalidateblock',h)
                    before=time.perf_counter()
                    try:
                        stock.mine(tx); row['stock_block_accepted']=True
                    except RPCError as error:
                        row.update(stock_block_accepted=False,stock_block_error=error.error)
                    row['stock_block_timing']=timing(before)
                    result['cases'].append(row); save()
                    if row['toy_native']['valid']!=expected or row['toy_block_accepted']!=expected or row['stock_native']['valid'] or row['stock_block_accepted']:
                        raise AssertionError(f'validation mismatch: {name}: {row}')
                    return row

                def assemble(instance,tx,pin_hit,digest_hit,subset,preimages=None):
                    pin_z=bytes.fromhex(pin_hit['digest_hex']); digest_z=bytes.fromhex(digest_hit['digest_hex'])
                    pin=(pin_z,instance.proof_key(tx,pin_z)); digest=(digest_z,instance.proof_key(tx,digest_z))
                    tx.inputs[1].script=instance.witness(pin,digest,subset,preimages)
                    return pin,digest

                def lifecycle(bits,value,label):
                    instance=instances[bits]; tx=base(bits,value)
                    row=dict(name=label,bits=bits,authorization='full public HORS table available',attempts=[])
                    result['lifecycles'].append(row); next_counter=0
                    while True:
                        print(f'toy: {label}: pinning b={bits}',flush=True)
                        pin=search(instance,tx,'pin',max_candidates,max_seconds,next_counter)
                        attempt=dict(pinning=pin); row['attempts'].append(attempt); save()
                        if not pin['found']: raise RuntimeError(f'{label}: pinning budget exhausted')
                        print(f'toy: {label}: subset search after {pin["measurement"]["candidates"]:,} pinning candidates',flush=True)
                        digest=search(instance,tx,'subset',max_candidates,max_seconds)
                        attempt['digest_subset']=digest; save()
                        if digest['found']: break
                        if digest['budget_exhausted']: raise RuntimeError(f'{label}: subset budget exhausted')
                        next_counter=pin['winning_counter']+1
                    subset=digest['selected_indices']
                    before=time.perf_counter(); pin_w,digest_w=assemble(instance,tx,pin['hit'],digest['hit'],subset)
                    row.update(assembly=timing(before),selected_indices=subset,sequence=tx.inputs[1].sequence,
                               disclosed_preimages={str(i):instance.preimages[i].hex() for i in subset})
                    checked=validate(label,tx,True)
                    row.update(native_verification=checked['toy_native_timing'],block_acceptance=checked['toy_block_timing'],
                               transaction_file=checked['file'])
                    return tx,pin_w,digest_w,subset

                for bits,instance in instances.items():
                    tx,pin,digest,subset=lifecycle(bits,1_980_000,f'b{bits}-honest')
                    bad=deepcopy(tx); bad.outputs[0].value-=1
                    validate(f'b{bits}-changed-amount-stale-witness',bad,False)
                    bad.inputs[1].script=instance.witness((instance.digest(bad),pin[1]),(instance.digest(bad,subset),digest[1]),subset)
                    validate(f'b{bits}-changed-amount-recovered-keys-stale-proof-keys',bad,False)
                    corrupt={i:instance.preimages[i] for i in subset}; corrupt[subset[0]]=bytes(32)
                    bad=deepcopy(tx); bad.inputs[1].script=instance.witness(pin,digest,subset,corrupt)
                    validate(f'b{bits}-wrong-hors-preimage',bad,False)
                    changed_subset=next(s for s in combinations(range(instance.params.entries),instance.params.selections) if list(s)!=subset)
                    bad=deepcopy(tx); bad.inputs[1].script=instance.witness(pin,digest,changed_subset)
                    validate(f'b{bits}-changed-subset-stale-key',bad,False)
                    duplicate=[subset[0]]*len(subset)
                    bad=deepcopy(tx); bad.inputs[1].script=instance.witness(pin,digest,duplicate)
                    validate(f'b{bits}-duplicate-index',bad,False)
                    if bits in levels:
                        lifecycle(bits,1_979_999,f'b{bits}-authorized-modified')
                    if bits in reuse_bits:
                        # Only this restricted mapping is given to witness assembly.
                        disclosed={i:instance.preimages[i] for i in subset}
                        for trial in range(reuse_trials):
                            label=f'b{bits}-frozen-reuse-{trial+1}'
                            modified=base(bits,1_979_900-trial)
                            print(f'toy: {label}: searching with only original disclosed subset {subset}',flush=True)
                            stats=search(instance,modified,'frozen',max_candidates,max_seconds,frozen=subset)
                            row=dict(name=label,bits=bits,trial=trial+1,search=stats,selected_indices=subset,
                                     source_transaction=tx.txid,disclosed_preimages={str(i):p.hex() for i,p in disclosed.items()},
                                     unrevealed_preimages_supplied_to_search=False,
                                     authorization='original subset and identical preimage bytes only')
                            result['frozen_disclosure'].append(row); save()
                            if not stats['found']: raise RuntimeError(f'{label}: frozen-disclosure budget exhausted')
                            before=time.perf_counter()
                            assemble(instance,modified,stats['hit'],stats['digest_hit'],subset,disclosed)
                            row['assembly']=timing(before)
                            old_auth=authorization_bytes(tx,len(subset)); new_auth=authorization_bytes(modified,len(subset))
                            row['authorization_bytes_identical']=old_auth==new_auth
                            row['authorization_hex']=new_auth.hex()
                            if old_auth!=new_auth: raise AssertionError('frozen experiment changed disclosed authorization bytes')
                            checked=validate(label,modified,True)
                            row.update(native_verification=checked['toy_native_timing'],block_acceptance=checked['toy_block_timing'],
                                       transaction_file=checked['file'])
        result['replay']=replay(outdir,bitcoind,result)
        result['status']='complete_toy_experiment'; save(final=True)
        (outdir/'partial-results.json').unlink(missing_ok=True)
        return result
    except BaseException as error:
        result.update(status='incomplete',failure=str(error)); save()
        raise


def replay(outdir,bitcoind='bitcoind',result=None):
    start=time.perf_counter(); outdir=Path(outdir)
    result=result or json.loads((outdir/'results.json').read_text())
    rows=[]
    with Core(bitcoind) as stock, Core(str(toy_build.NODE),create_wallet=False,mining_address=result['mining_address']) as toy:
        for node in (stock,toy):
            for path in result['setup_blocks']:
                if node.rpc('submitblock',(outdir/path).read_text().strip()) is not None:
                    raise AssertionError('setup replay rejected')
            if node.rpc('getbestblockhash')!=result['base_tip']: raise AssertionError('replay base mismatch')
        for case in result['cases']:
            tx=Tx.parse((outdir/case['file']).read_text().strip())
            if tx.txid!=case['transaction']['txid']: raise AssertionError('transaction fixture id mismatch')
            native_toy=verify(outdir/case['file'],[outdir/'funding.hex']*2,toy_build.VERIFIER)
            native_stock=verify(outdir/case['file'],[outdir/'funding.hex']*2)
            if native_toy['valid']!=case['toy_block_accepted'] or native_stock['valid']:
                raise AssertionError('native replay mismatch')
            row=dict(name=case['name'],toy_accepted=case['toy_block_accepted'],stock_accepted=False,reproduced=True)
            if case['toy_block_accepted']:
                block=(outdir/case['block_file']).read_text().strip()
                outcome=toy.rpc('submitblock',block)
                if outcome is not None or toy.rpc('getbestblockhash')!=case['blockhash'] or tx.txid not in toy.rpc('getblock',case['blockhash'],1)['tx']:
                    raise AssertionError('experimental accepted-block replay failed')
                toy.rpc('invalidateblock',case['blockhash'])
                # Submit the very same accepted block to stock Core, beyond the
                # generateblock rejection already recorded during the run.
                rejection=stock.rpc('submitblock',block)
                if rejection is None or stock.rpc('getbestblockhash')!=result['base_tip']:
                    raise AssertionError('stock Core accepted an experimental block')
                row['stock_submitblock_rejection']=rejection
            else:
                try: toy.mine(tx)
                except RPCError: pass
                else: raise AssertionError('previously rejected experimental spend accepted')
            rows.append(row)
    return dict(consensus_modified=True,qsb_exact_reproduction=False,setup_blocks_per_node=len(result['setup_blocks']),
                cases=rows,wall_seconds=time.perf_counter()-start)
