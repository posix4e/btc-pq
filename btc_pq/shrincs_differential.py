"""Replay identical SHRINCS bytes through C++, C, and pure Python verifiers."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import tempfile

from .crypto import ROOT
from .shrincs_build import SHRINCS_COMMIT, UPSTREAM
from .shrincs_c import CVerifier, COMMIT as C_COMMIT
from .shrincs_demo import native_tool
from .shrincs_kat import parse_vectors
from .shrincs_reference import verify


def replay(path, *, expected_count):
    path = Path(path)
    records = parse_vectors(path.read_text())
    if len(records) != expected_count or [int(r['count']) for r in records] != list(range(expected_count)):
        raise ValueError('vector count or sequence mismatch')
    c = CVerifier()
    cases, controls, noncanonical = [], 0, []
    with tempfile.TemporaryDirectory() as directory:
        pk_path, msg_path, sig_path = [Path(directory)/name for name in ('pk.hex', 'msg.hex', 'sig.hex')]
        def check(message, signature, key, expected):
            for p, value in ((pk_path, key), (msg_path, message), (sig_path, signature)):
                p.write_text(value.hex()+'\n')
            python_result = verify(message, signature, key)
            verdicts = dict(cpp=native_tool('verify', pk_path, msg_path, sig_path)['valid'],
                            c=c.verify(message, signature, key), python=python_result['valid'])
            if any(value != expected for value in verdicts.values()):
                raise AssertionError(dict(expected=expected, verdicts=verdicts))
            return python_result
        for r in records:
            m, s, p = [bytes.fromhex(r[k]) for k in ('msg', 'sig', 'pk')]
            if r['result'] != 'Pass' or len(m) != int(r['mlen']) or len(s) != int(r['siglen']):
                raise ValueError('malformed upstream vector')
            work = check(m, s, p, True)
            for mm, ss, pp in ((bytes([m[0]^1])+m[1:], s, p),
                               (m, bytes([s[0]^1])+s[1:], p),
                               (m, s, p[:16]+bytes([p[16]^1])+p[17:]),
                               (m, s[:-1], p), (m, s+b'\0', p)):
                check(mm, ss, pp, False)
                controls += 1
            if len(s) == 3680:
                changed = bytearray(s)
                changed[16+1984] ^= 1
                check(m, bytes(changed), p, True)
                noncanonical.append(int(r['count']))
            cases.append(dict(count=int(r['count']), label=r['label'], message_bytes=len(m),
                              signature_bytes=len(s), all_three_verified=True, python_work=work))
    result = dict(parameters='SHRINCS_B32', cpp_commit=SHRINCS_COMMIT, c_commit=C_COMMIT,
                  python_source_sha256=sha256((ROOT/'btc_pq/shrincs_reference.py').read_bytes()).hexdigest(),
                  vectors_sha256=sha256(path.read_bytes()).hexdigest(),
                  generator_source_sha256=sha256((UPSTREAM/'kat/kat_gen_pass.cpp').read_bytes()).hexdigest(),
                  full_upstream_pass_generator=expected_count == 375,
                  independent_security_audit=False,
                  scope='Separate C++ and C implementations plus a locally authored Python verifier; not an independent cryptographic audit.',
                  generator_display_name='L; compiled parameters are B32', cases=cases,
                  negative_controls=controls,
                  negative_control_types=['message', 'signature-root', 'public-key-root', 'truncate', 'append'],
                  accepted_internal_randomness_mutations=noncanonical,
                  all_expectations_met=True)
    output = path.with_name(path.stem+'-differential.json')
    output.write_text(json.dumps(result, indent=2)+'\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--path', type=Path, default=ROOT/'results/shrincs-demo/upstream-kat.rsp')
    parser.add_argument('--expected-count', type=int, choices=(15, 375), default=15)
    args = parser.parse_args()
    result = replay(args.path, expected_count=args.expected_count)
    print(f"Three implementations: {len(result['cases'])} vectors, {result['negative_controls']} negative controls passed")
