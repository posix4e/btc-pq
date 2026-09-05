"""Small strict transaction codec and legacy sighash implementation for experiments.

Script validity is ALWAYS decided by Bitcoin Core, never by this module.
"""
from dataclasses import dataclass, field
from hashlib import sha256
from io import BytesIO
import struct


def hash256(b):
    return sha256(sha256(b).digest()).digest()


def compact(n):
    if n < 253:
        return bytes([n])
    if n <= 65535:
        return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)


def blob(b):
    return compact(len(b)) + b


class Reader:
    def __init__(self, data):
        self.f = BytesIO(data)

    def read(self, n):
        b = self.f.read(n)
        if len(b) != n:
            raise ValueError('truncated transaction')
        return b

    def number(self, fmt):
        return struct.unpack(fmt, self.read(struct.calcsize(fmt)))[0]

    def compact(self):
        n = self.read(1)[0]
        if n < 253:
            return n
        v = self.number({253: '<H', 254: '<I', 255: '<Q'}[n])
        if v < {253: 253, 254: 65536, 255: 2**32}[n]:
            raise ValueError('noncanonical compact size')
        return v

    def blob(self):
        return self.read(self.compact())


@dataclass
class Input:
    txid: str
    vout: int
    script: bytes = b''
    sequence: int = 0xfffffffe
    witness: list = field(default_factory=list)

    def serialize(self):
        return bytes.fromhex(self.txid)[::-1] + struct.pack('<I', self.vout) + blob(self.script) + struct.pack('<I', self.sequence)


@dataclass
class Output:
    value: int
    script: bytes

    def serialize(self):
        return struct.pack('<q', self.value) + blob(self.script)


@dataclass
class Tx:
    inputs: list
    outputs: list
    version: int = 2
    locktime: int = 0

    def serialize(self, witness=True):
        has_witness = witness and any(i.witness for i in self.inputs)
        b = struct.pack('<i', self.version) + (b'\x00\x01' if has_witness else b'')
        b += compact(len(self.inputs)) + b''.join(i.serialize() for i in self.inputs)
        b += compact(len(self.outputs)) + b''.join(o.serialize() for o in self.outputs)
        if has_witness:
            for i in self.inputs:
                b += compact(len(i.witness)) + b''.join(blob(w) for w in i.witness)
        return b + struct.pack('<I', self.locktime)

    @property
    def txid(self):
        return hash256(self.serialize(False))[::-1].hex()

    def metrics(self):
        stripped, total = len(self.serialize(False)), len(self.serialize())
        weight = stripped * 3 + total
        return dict(txid=self.txid, bytes=total, stripped_bytes=stripped, weight=weight,
                    vsize=(weight + 3)//4, input_script_bytes=[len(i.script) for i in self.inputs],
                    output_script_bytes=[len(o.script) for o in self.outputs])

    @classmethod
    def parse(cls, raw):
        r = Reader(bytes.fromhex(raw) if isinstance(raw, str) else raw)
        version = r.number('<i')
        n = r.compact()
        witness = n == 0
        if witness:
            if r.read(1) != b'\x01':
                raise ValueError('unsupported witness flag')
            n = r.compact()
        inputs = [Input(r.read(32)[::-1].hex(), r.number('<I'), r.blob(), r.number('<I')) for _ in range(n)]
        outputs = [Output(r.number('<q'), r.blob()) for _ in range(r.compact())]
        if witness:
            for i in inputs:
                i.witness = [r.blob() for _ in range(r.compact())]
            if not any(i.witness for i in inputs):
                raise ValueError('superfluous witness serialization')
        tx = cls(inputs, outputs, version, r.number('<I'))
        if r.f.read():
            raise ValueError('trailing transaction bytes')
        return tx


def push(b):
    n = len(b)
    if n < 76:
        return bytes([n]) + b
    if n <= 255:
        return b'\x4c' + bytes([n]) + b
    if n <= 65535:
        return b'\x4d' + struct.pack('<H', n) + b
    raise ValueError('push too long')


def num(n):
    if n == 0:
        return b'\x00'
    if 1 <= n <= 16:
        return bytes([0x50 + n])
    if n < 0:
        raise ValueError('only nonnegative script numbers supported')
    b = n.to_bytes((n.bit_length()+7)//8, 'little')
    return push(b + (b'\x00' if b[-1] & 128 else b''))


def instructions(script):
    r = Reader(script)
    while r.f.tell() < len(script):
        start = r.f.tell()
        op = r.read(1)[0]
        data = None
        if op <= 75:
            data = r.read(op)
        elif op in (76, 77, 78):
            data = r.read(r.number({76:'<B',77:'<H',78:'<I'}[op]))
        yield start, op, data, r.f.tell()


def script_metrics(script):
    ins = list(instructions(script))
    return dict(bytes=len(script), static_non_push_opcodes=sum(op > 0x60 for _, op, _, _ in ins),
                max_push_bytes=max((len(data) for _, _, data, _ in ins if data is not None), default=0),
                checksig_count=sum(op in (0xac,0xad) for _,op,_,_ in ins),
                checkmultisig_count=sum(op in (0xae,0xaf) for _,op,_,_ in ins))


def legacy_sighash(tx, index, script, signature=b'', hash_type=1):
    """Includes legacy FindAndDelete; supports ALL/NONE/SINGLE/ANYONECANPAY."""
    from copy import deepcopy
    if index >= len(tx.inputs):
        return b'\x01' + bytes(31)
    target = push(signature) if signature else None
    script = b''.join(script[a:b] for a, op, _, b in instructions(script)
                      if op != 0xab and script[a:b] != target)
    t = deepcopy(tx)
    for i in t.inputs:
        i.script = b''
        i.witness = []
    t.inputs[index].script = script
    mode = hash_type & 31
    if mode == 2:
        t.outputs = []
    elif mode == 3:
        if index >= len(t.outputs):
            return b'\x01' + bytes(31)
        t.outputs = [Output(-1,b'') for _ in range(index)] + [t.outputs[index]]
    if mode in (2,3):
        for j, i in enumerate(t.inputs):
            if j != index:
                i.sequence = 0
    if hash_type & 128:
        t.inputs = [t.inputs[index]]
    return hash256(t.serialize(False) + struct.pack('<I', hash_type))
