"""Standalone Python SHRINCS-B32 verifier and SHA256 work counter.

Implements the pinned algorithm with immutable addresses and a dictionary-based
Merkle proof reconstruction. It does not call either native implementation.
This is implementation diversity for testing, not an independent security audit.
"""
from hashlib import sha256
from hmac import compare_digest
import struct

N, W, L, SWN, HSF, HSL, D = 16, 256, 16, 2040, 210, 32, 4
T, B, K, M_MAX = 109571, 17, 11, 111
WOTS_SIZE, XMSS_SIZE, PORS_SIZE, RECOVERY_SIZE = 292, 420, 1984, 3680
XOF_OFFSET = (((2**B * K + T - 1)//T + 10) * B + 16)
XOF_BLOCKS = (XOF_OFFSET + HSL + 255)//256


class InvalidSignature(ValueError):
    pass


class Verifier:
    def __init__(self, public_key):
        if len(public_key) != 32:
            raise InvalidSignature('public key length')
        self.seed, self.root = public_key[:N], public_key[N:]
        self.base = sha256(self.seed + bytes(48))
        self.hash_calls = 0
        self.compression_blocks = 1  # Shared, precomputed 64-byte prefix.
        self.wots_attempts = 0
        self.pors_auth_nodes = 0
        self.pors_root_height = 0
        self.xof_blocks = 0

    def h(self, kind, payload, *, layer=0, tree=0, keypair=0, a=0, b=0, full=False):
        address = struct.pack('>I', layer) + tree.to_bytes(12, 'big')
        address += struct.pack('>IIII', kind, keypair, a, b)
        self.hash_calls += 1
        self.compression_blocks += (len(address) + len(payload) + 9 + 63)//64
        context = self.base.copy()
        context.update(address)
        context.update(payload)
        digest = context.digest()
        return digest if full else digest[:N]

    def wots(self, signature, message, *, stateful, keypair, layer=0, tree=0):
        if len(signature) != WOTS_SIZE:
            raise InvalidSignature('WOTS length')
        self.wots_attempts += 1
        randomness, counter = signature[:32], signature[32:36]
        if stateful:
            digest = self.h(4, randomness + self.root + message, layer=layer, tree=tree)
            hash_kind, pk_kind, grind_kind = 0, 1, 3
        else:
            if len(message) != N:
                raise InvalidSignature('internal message length')
            digest = message
            hash_kind, pk_kind, grind_kind = 11, 12, 14
        digits = self.h(grind_kind, digest + counter, layer=layer, tree=tree, keypair=keypair)
        if sum(digits) != SWN:
            raise InvalidSignature('WOTS checksum target')
        tips = []
        for chain, digit in enumerate(digits):
            node = signature[36 + chain*N:36 + (chain+1)*N]
            for step in range(digit, W-1):
                node = self.h(hash_kind, node, layer=layer, tree=tree,
                              keypair=keypair, a=chain, b=step)
            tips.append(node)
        return self.h(pk_kind, b''.join(tips), layer=layer, tree=tree, keypair=keypair)

    def compact(self, message, signature):
        q = (len(signature)-N-WOTS_SIZE)//N
        auth = [signature[i:i+N] for i in range(N+WOTS_SIZE, len(signature), N)]
        # Both final leaves encode the same number of authentication nodes.
        for candidate in ([HSF, HSF+1] if q == HSF else [q]):
            try:
                node = self.wots(signature[N:N+WOTS_SIZE], message,
                                 stateful=True, keypair=candidate)
                for i, sibling in enumerate(auth):
                    if candidate <= HSF:
                        height = HSF + 1 - candidate + i
                        pair = node + sibling if i == 0 else sibling + node
                    else:
                        height, pair = i+1, sibling+node
                    node = self.h(2, pair, a=height)
                root = self.h(17, node+signature[:N])
                if compare_digest(root, self.root):
                    return True
            except InvalidSignature:
                continue
        return False

    def indices(self, digest):
        selected, blocks = set(), []
        # The upstream algorithm may keep sampling after the fixed XOF prefix.
        for counter in range(2**32):
            block = self.h(10, digest + counter.to_bytes(4, 'big'), full=True)
            self.xof_blocks += 1
            if counter < XOF_BLOCKS:
                blocks.append(block)
            for offset in range(256//B):
                candidate = (int.from_bytes(block, 'big') >> (256-(offset+1)*B)) & (2**B-1)
                if len(selected) == K:
                    break
                if candidate < T:
                    selected.add(candidate)
            # Upstream evaluates one extra block even when K were found early.
            if len(selected) == K and counter >= XOF_BLOCKS:
                prefix = b''.join(blocks)
                tree = (int.from_bytes(prefix, 'big') >> (8*len(prefix)-XOF_OFFSET-HSL)) & (2**HSL-1)
                return sorted(selected), tree
        raise InvalidSignature('PORS index exhaustion')

    def pors(self, signature, indices, tree):
        split = T - 2**(B-1)
        nodes = {}
        for position, index in enumerate(indices):
            secret = signature[32+N*position:32+N*(position+1)]
            leaf = self.h(6, secret, tree=tree, b=index)
            location = (0, index) if index < 2*split else (1, index-split)
            nodes[location] = leaf
        cursor = 32+N*K
        for level in range(B):
            current = sorted(index for height, index in nodes if height == level)
            for index in current:
                location = (level, index)
                if location not in nodes:
                    continue  # This node was paired by its sibling.
                node = nodes.pop(location)
                sibling = nodes.pop((level, index^1), None)
                if sibling is None:
                    if cursor+N > len(signature):
                        raise InvalidSignature('PORS authentication path exhausted')
                    sibling = signature[cursor:cursor+N]
                    cursor += N
                    self.pors_auth_nodes += 1
                pair = node+sibling if index%2 == 0 else sibling+node
                parent = (level+1, index//2)
                if parent in nodes:
                    raise InvalidSignature('overlapping Merkle nodes')
                nodes[parent] = self.h(7, pair, tree=tree, a=level+1, b=index//2)
            # The pinned algorithm terminates when its frontier is one node at
            # index zero, even below B if all selected leaves were in that
            # subtree. Its signer and XMSS layer bind that resulting PORS key.
            if len(nodes) == 1 and (level+1, 0) in nodes:
                self.pors_root_height = level+1
                break
        if not self.pors_root_height or any(signature[cursor:]):
            raise InvalidSignature('PORS root or padding')
        return self.h(8, nodes[(self.pors_root_height, 0)], tree=tree)

    def recovery(self, message, signature):
        pors = signature[N:N+PORS_SIZE]
        digest = self.h(15, pors[:32] + self.root + message, full=True)
        indices, tree_index = self.indices(digest)
        node = self.pors(pors, indices, tree_index)
        for layer in range(D):
            leaf_index = tree_index & 255
            tree_index >>= 8
            offset = N+PORS_SIZE + layer*XMSS_SIZE
            xmss = signature[offset:offset+XMSS_SIZE]
            node = self.wots(xmss[:WOTS_SIZE], node, stateful=False,
                             keypair=leaf_index, layer=layer, tree=tree_index)
            for height in range(1, 9):
                sibling = xmss[WOTS_SIZE+(height-1)*N:WOTS_SIZE+height*N]
                pair = node+sibling if leaf_index%2 == 0 else sibling+node
                leaf_index >>= 1
                node = self.h(13, pair, layer=layer, tree=tree_index, a=height, b=leaf_index)
        return compare_digest(self.h(17, signature[:N]+node), self.root)


def verify(message, signature, public_key):
    result = dict(valid=False, mode='invalid', hash_calls=0, compression_blocks=0,
                  wots_attempts=0, pors_auth_nodes=0, pors_root_height=0, xof_blocks=0)
    size = len(signature)
    compact = 324 <= size <= 3668 and (size-308)%16 == 0
    if len(public_key) != 32 or not (compact or size == RECOVERY_SIZE):
        return result
    verifier = Verifier(public_key)
    result['mode'] = 'compact' if compact else 'recovery'
    try:
        result['valid'] = verifier.compact(message, signature) if compact else verifier.recovery(message, signature)
    except InvalidSignature:
        pass
    for key in ('hash_calls', 'compression_blocks', 'wots_attempts', 'pors_auth_nodes', 'pors_root_height', 'xof_blocks'):
        result[key] = getattr(verifier, key)
    return result
