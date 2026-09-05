"""Concrete candidate compilers, including deliberately disconnected encodings.

The short Lamport/WOTS instances are attack diagnostics, NOT security demos.
"""
from hashlib import sha256
from .bitcoin import push, num, script_metrics, legacy_sighash
from .crypto import FIXED_SIG, FIXED_R, encode, recover, secret

SUFFIX = push(FIXED_SIG) + b'\x7c\xac'  # fixed signature, SWAP, CHECKSIG
CHECK = b'\xab' + SUFFIX  # CODESEPARATOR intentionally removes auth prefix from scriptCode


def recovered(tx, recovery_id=0, encoding='compressed', hash_type=1):
    digest=legacy_sighash(tx,0,SUFFIX,FIXED_SIG,hash_type)
    q=recover(FIXED_R,1,digest,recovery_id)
    if q is None:
        raise ValueError('invalid recovery branch')
    return encode(q,encoding)


def whole_key(commitment):
    return b'\x76\xa8' + push(commitment) + b'\x88' + CHECK


def lamport_script(bits):
    script=b''
    for j in range(bits):
        h0=sha256(secret(f'lamport/{j}/0')).digest()
        h1=sha256(secret(f'lamport/{j}/1')).digest()
        # IF h1 ELSE h0 ENDIF SWAP SHA256 EQUALVERIFY
        script += b'\x63'+push(h1)+b'\x67'+push(h0)+b'\x68\x7c\xa8\x88'
    return script+CHECK


def lamport_witness(key, bits):
    message=[(byte >> shift)&1 for byte in key for shift in range(7,-1,-1)][-bits:]
    return b''.join(push(secret(f'lamport/{j}/{b}'))+num(b) for j,b in reversed(list(enumerate(message))))


def chain(value, steps):
    for _ in range(steps):
        value=sha256(value).digest()
    return value


def checksum_digits(count, radix=4):
    n=1
    while radix**n <= count*(radix-1):
        n+=1
    return n


def wots_script(message_digits):
    count=message_digits+checksum_digits(message_digits)
    script=b'\x00\x6b'  # message sum on altstack
    for j in range(count):
        if j==message_digits:
            script+=b'\x00\x6b'  # checksum accumulator above message sum
        script+=b'\x76'+num(0)+num(4)+b'\xa5\x69'  # DUP 0 4 WITHIN VERIFY
        if j < message_digits:
            script+=b'\x76\x6c\x93\x6b'  # DUP FROMALTSTACK ADD TOALTSTACK
        else:
            # Horner base 4 checksum, preserving digit for the hash chain.
            script+=b'\x6c\x76\x93\x76\x93\x78\x93\x6b'
        for threshold in range(3):
            script+=b'\x76'+num(threshold)+b'\xa1\x63\x7c\xa8\x7c\x68'
        script+=b'\x75'+push(chain(secret(f'wots/{j}'),3))+b'\x88'
    # Message sum + checksum must equal 3 * message length.
    script+=b'\x6c\x6c\x93'+num(3*message_digits)+b'\x88'
    return script+CHECK


def wots_digits(key, count):
    digits=[(byte >> shift)&3 for byte in key for shift in (6,4,2,0)][-count:]
    checksum=sum(3-d for d in digits)
    n=checksum_digits(count)
    return digits+[(checksum >> (2*j))&3 for j in range(n-1,-1,-1)]


def wots_witness(key, count):
    digits=wots_digits(key,count)
    return b''.join(push(chain(secret(f'wots/{j}'),d))+num(d) for j,d in reversed(list(enumerate(digits))))


def limits():
    rows=[]
    for name,script in [('lamport_full_264_bits',lamport_script(264)),
                        ('wots_base4_full_132_digits_plus_checksum',wots_script(132)),
                        ('lamport_diagnostic_8_bits',lamport_script(8)),
                        ('wots_diagnostic_2_digits_plus_checksum',wots_script(2))]:
        m=script_metrics(script)
        rows.append(dict(name=name, **m, within_script_size=m['bytes']<=10000,
                         within_opcode_count=m['static_non_push_opcodes']<=201,
                         message_key_binding=False))
    return rows
