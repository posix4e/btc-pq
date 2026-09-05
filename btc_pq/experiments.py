"""Block-validated counterexamples. Every fixture uses valueless regtest coins."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import time
from .bitcoin import Tx, Input, Output, push, num, script_metrics
from .crypto import FIXED_SIG, ROOT, secret, ec, encode
from .candidates import CHECK, whole_key, recovered, lamport_script, lamport_witness, wots_script, wots_witness, limits
from .core import Core, RPCError, verify


def write_tx(path, tx):
    path.write_text(tx.serialize().hex()+'\n')
    return path


def run(outdir, bitcoind='bitcoind'):
    outdir=Path(outdir); outdir.mkdir(parents=True, exist_ok=True)
    blocks=outdir/'blocks'; blocks.mkdir(exist_ok=True)
    start=time.perf_counter()
    initial_key=encode(ec.G)
    scripts={
        'direct':CHECK,
        'lamport':lamport_script(8),
        'winternitz':wots_script(2),
        'whole_key':whole_key(sha256(initial_key).digest()),
        'lamport_full':lamport_script(264),
        'winternitz_full':wots_script(132),
        'disabled_cat':b'\x7e\x75\x51',
        'oversized_element':b'\x75\x51',
        'stack_limit':b'\x51',
    }
    setup_seconds=time.perf_counter()-start
    result=dict(scope='counterexamples_and_feasibility_limits_only', secure_candidate_demonstrated=False,
                fixed_signature=FIXED_SIG.hex(), fixed_sighash='SIGHASH_ALL',
                setup_compile_cpu_wall_seconds=setup_seconds, compiler_limits=limits(), cases=[],
                reduced_instances='Lamport signs the last 8 key bits; WOTS signs the last 2 base-4 digits with checksum. Attack diagnostics only.',
                consensus_changes=[], relay_policy_changes=[],
                block_method='generateblock submits to Core; accepted blocks saved and invalidated to test mutually exclusive spends')
    with Core(bitcoind) as core:
        result['core_version']=core.info['version']
        core.rpc('generatetoaddress',101,core.address)
        utxo=sorted(core.rpc('listunspent',100),key=lambda x:x['txid'])[0]
        outputs=[]; indices={}
        # Two identical outputs per family allow an actual funded input substitution.
        for name, script in scripts.items():
            indices[name]=len(outputs)
            outputs.extend([Output(1_000_000,script),Output(1_000_000,script)])
        change=bytes.fromhex(core.rpc('getaddressinfo',core.address)['scriptPubKey'])
        value=round(utxo['amount']*100_000_000)
        outputs.append(Output(value-sum(o.value for o in outputs)-10_000,change))
        funding=Tx([Input(utxo['txid'],utxo['vout'])], outputs)
        signed=core.rpc('signrawtransactionwithwallet',funding.serialize().hex())
        if not signed['complete']:
            raise RuntimeError('regtest funding not signed')
        funding=Tx.parse(signed['hex'])
        funding_path=write_tx(outdir/'funding.hex',funding)
        (outdir/'funding-parent.hex').write_text(core.rpc('gettransaction',utxo['txid'])['hex']+'\n')
        funding_block=core.mine(funding)
        result['funding']=dict(**funding.metrics(), output_indices=indices, blockhash=funding_block,
                               script_metrics={name:script_metrics(s) for name,s in scripts.items()})
        # Preserve the complete small chain, including coinbase maturity.
        result['setup_blocks']=[]
        for height in range(1,core.rpc('getblockcount')+1):
            h=core.rpc('getblockhash',height)
            path=blocks/f'setup-{height:03}.hex'
            path.write_text(core.rpc('getblock',h,0)+'\n')
            result['setup_blocks'].append(str(path.relative_to(outdir)))
        base_tip=core.rpc('getbestblockhash')
        result['base_tip']=base_tip
        result['regtest_deployments']=core.rpc('getdeploymentinfo')

        def base(name):
            return Tx([Input(funding.txid,indices[name])],[Output(990_000,b'\x51')])

        def case(family,name,tx,expected,detail=None):
            if core.rpc('getbestblockhash')!=base_tip:
                raise AssertionError('experiment chain was not restored')
            label=family+'--'+name
            path=write_tx(outdir/(label+'.hex'),tx)
            native=verify(path,[funding_path]*len(tx.inputs))
            before=time.perf_counter()
            blockhash=None; error=None
            try:
                blockhash=core.mine(tx)
                accepted=True
            except RPCError as e:
                accepted=False; error=e.error
            row=dict(family=family,name=name,expected_acceptance=expected,block_accepted=accepted,
                     native=native,transaction=tx.metrics(),file=path.name,
                     block_validation_wall_seconds=time.perf_counter()-before,detail=detail)
            if accepted:
                if core.rpc('getbestblockhash')!=blockhash:
                    raise AssertionError('generated block not active')
                included=core.rpc('getblock',blockhash,1)['tx']
                if tx.txid not in included:
                    raise AssertionError('spend missing from accepted block')
                blockpath=blocks/(label+'.hex')
                blockpath.write_text(core.rpc('getblock',blockhash,0)+'\n')
                row.update(blockhash=blockhash, block_file=str(blockpath.relative_to(outdir)))
                core.rpc('invalidateblock',blockhash)
            else:
                row['block_rejection']=error
            result['cases'].append(row)
            if accepted!=expected or native['valid']!=expected:
                (outdir/'partial-results.json').write_text(json.dumps(result,indent=2)+'\n')
                raise AssertionError(f'{label}: expected {expected}, native {native}, block {error or accepted}')

        for family in ('direct','lamport','winternitz'):
            tx=base(family)
            t=time.perf_counter(); key=recovered(tx)
            recovery_seconds=time.perf_counter()-t
            t=time.perf_counter()
            auth=(lamport_witness(key,8) if family=='lamport' else wots_witness(key,2) if family=='winternitz' else b'')
            auth_seconds=time.perf_counter()-t
            tx.inputs[0].script=push(key)+auth
            case(family,'honest_diagnostic',tx,True,dict(recovery_cpu_wall_seconds=recovery_seconds,
                 ots_sign_cpu_wall_seconds=auth_seconds,key=key.hex(),authorization_hex=auth.hex()))
            for name,mutate in [
                ('redirect_with_stale_key',lambda v:setattr(v.outputs[0],'script',b'\x00')),
                ('amount_with_stale_key',lambda v:setattr(v.outputs[0],'value',989_999)),
                ('input_with_stale_key',lambda v:setattr(v.inputs[0],'vout',indices[family]+1))]:
                v=deepcopy(tx); mutate(v); case(family,name,v,False)
                v.inputs[0].script=push(recovered(v))+auth
                case(family,name.replace('stale_key','recovered_key'),v,True,
                     'Identical authorization bytes reused for a different transaction and recovered key.')
            for recovery_id in range(1,4):
                v=deepcopy(tx); other=recovered(v,recovery_id)
                v.inputs[0].script=push(other)+auth
                case(family,f'recovery_branch_{recovery_id}',v,True,dict(key=other.hex(),same_authorization=True))
            for encoding in ('uncompressed','hybrid'):
                v=deepcopy(tx); other=recovered(v,encoding=encoding)
                v.inputs[0].script=push(other)+auth
                case(family,encoding,v,True,'Consensus legacy encoding; may be rejected by relay policy.')
            for hash_type in (2,3,0x81):
                v=deepcopy(tx); v.inputs[0].script=push(recovered(v,hash_type=hash_type))+auth
                case(family,f'sighash_substitution_{hash_type}',v,False,
                     'Recover under a different sighash while Script retains its fixed ALL signature.')
            v=deepcopy(tx); v.inputs[0].witness=[b'wrong-message']
            case(family,'unexpected_witness',v,False)
            v=deepcopy(tx); malformed=bytearray(key); malformed[0]=5
            v.inputs[0].script=push(bytes(malformed))+auth
            case(family,'invalid_key_serialization',v,False)
            if auth:
                v=deepcopy(tx); corrupt=bytearray(auth); corrupt[1]^=1
                v.inputs[0].script=push(key)+bytes(corrupt)
                case(family,'wrong_preimage',v,False)
                # Change the last supplied digit without changing the corresponding secret.
                v=deepcopy(tx); corrupt=bytearray(auth); corrupt[-1]=0x51 if corrupt[-1]==0 else 0
                v.inputs[0].script=push(key)+bytes(corrupt)
                case(family,'message_secret_mismatch',v,False)
        tx=base('whole_key'); key=recovered(tx); tx.inputs[0].script=push(key)
        case('whole_key','recover_after_funding',tx,False,'Actual recovered key does not match the pre-funded exact-byte commitment.')
        tx.inputs[0].script=push(initial_key)
        case('whole_key','committed_key_after_funding',tx,False,'The committed bytes pass authentication but fail the fixed signature.')
        trace=[]; hypothetical=deepcopy(funding)
        for step in range(8):
            spend=Tx([Input(hypothetical.txid,indices['whole_key'])],[Output(990_000,b'\x51')])
            key=recovered(spend)
            new_script=whole_key(sha256(key).digest())
            trace.append(dict(step=step,funding_txid=hypothetical.txid,recovered_key=key.hex(),
                              matches_commitment=hypothetical.outputs[indices['whole_key']].script==new_script))
            hypothetical.outputs[indices['whole_key']].script=new_script
        result['whole_key_dependency_trace']=dict(iterations=trace, solved=any(r['matches_commitment'] for r in trace),
            scope='Unsigned hypothetical funding revisions illustrate the dependency; not a convergence bound or impossibility proof.')
        for family,authfn in [('lamport_full',lambda k:lamport_witness(k,264)),('winternitz_full',lambda k:wots_witness(k,132))]:
            tx=base(family); key=recovered(tx); tx.inputs[0].script=push(key)+authfn(key)
            case(family,'consensus_limit',tx,False)
        tx=base('disabled_cat'); tx.inputs[0].script=push(b'a')+push(b'b')
        case('limits','op_cat_reconstruction',tx,False)
        tx=base('oversized_element'); tx.inputs[0].script=push(bytes(521))
        case('limits','521_byte_element',tx,False)
        tx=base('stack_limit'); tx.inputs[0].script=num(1)*1001
        case('limits','1001_stack_elements',tx,False)
    (outdir/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def replay(outdir,bitcoind='bitcoind'):
    """Replay saved funding chain and successful competing spends in a fresh node."""
    outdir=Path(outdir); result=json.loads((outdir/'results.json').read_text()); rows=[]
    with Core(bitcoind) as core:
        for path in result['setup_blocks']:
            outcome=core.rpc('submitblock',(outdir/path).read_text().strip())
            if outcome is not None:
                raise AssertionError(f'setup block rejected: {outcome}')
        if core.rpc('getbestblockhash')!=result['base_tip']:
            raise AssertionError('wrong setup tip')
        for row in result['cases']:
            if row['block_accepted']:
                outcome=core.rpc('submitblock',(outdir/row['block_file']).read_text().strip())
                if outcome is not None or core.rpc('getbestblockhash')!=row['blockhash']:
                    raise AssertionError(f'replay failed: {row["name"]}: {outcome}')
                core.rpc('invalidateblock',row['blockhash'])
            else:
                try:
                    core.mine(Tx.parse((outdir/row['file']).read_text().strip()))
                except RPCError:
                    pass
                else:
                    raise AssertionError('previously rejected transaction accepted')
            rows.append(dict(family=row['family'],name=row['name'],expected_acceptance=row['block_accepted'],reproduced=True))
    return dict(core_version=310100, setup_blocks_replayed=len(result['setup_blocks']), cases=rows)
