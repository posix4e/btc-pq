//! Exact SHA256 SHRINCS-B32 verification with the local opcode's work limits.
//! The hash callback is SHA256 on the host and the zkVM SHA256 accelerator in
//! the guest. Unlike the native checker, it recomputes the shared prefix; the
//! logical work counter retains the native model, not the VM cycle count.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

type Node = [u8; 16];
type Digest = [u8; 32];
type Check<T> = Result<T, ()>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Authorization {
    pub key: [u8; 32],
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Batch {
    pub authorizations: Vec<Authorization>,
}
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Work {
    pub valid: bool,
    pub compression_blocks: u64,
    pub hash_calls: u64,
    pub wots_attempts: u32,
    pub xof_blocks: u32,
    pub pors_auth_nodes: u32,
    pub pors_root_height: u32,
    pub work_bound: u64,
}

/// Ordered, length-delimited public claim statement. Signature bytes are
/// private witness; keys and transaction digests determine authorization.
pub fn claims_bytes(batch: &Batch) -> Check<Vec<u8>> {
    let count = batch.authorizations.len();
    if count == 0 || count > 512 {
        return Err(());
    }
    let mut bytes = b"btc-pq/SHRINCS-proof-claims/v1\0".to_vec();
    bytes.extend_from_slice(&(count as u32).to_le_bytes());
    for auth in &batch.authorizations {
        if auth.message.len() != 32 {
            return Err(());
        }
        bytes.extend_from_slice(&auth.key);
        bytes.extend_from_slice(&auth.message);
    }
    Ok(bytes)
}

pub fn work_bound(size: usize, message: usize) -> u64 {
    if message > 65536 {
        return 0;
    }
    let mb = ((32 + 32 + 16 + message + 9 + 63) / 64) as u64;
    if size == 3680 {
        return 1 + mb + 128 + 11 + 242 + 1 + 4 * 2062 + 2;
    }
    if !(324..=3668).contains(&size) || (size - 308) % 16 != 0 {
        return 0;
    }
    let q = ((size - 308) / 16) as u64;
    1 + (if q == 210 { 2 } else { 1 }) * (mb + 1 + 2040 + 5 + 2 * q + 2)
}

fn bits(bytes: &[u8], start: usize, count: usize) -> u32 {
    (start..start + count).fold(0, |value, bit| {
        (value << 1) | u32::from((bytes[bit / 8] >> (7 - bit % 8)) & 1)
    })
}

struct Verifier<F> {
    key: Digest,
    hash: F,
    work: Work,
}
impl<F: FnMut(&[u8]) -> Digest> Verifier<F> {
    // Address: layer, 64 zero tree bits, 32 tree bits, type, keypair, a, b.
    fn full(&mut self, addr: [u32; 6], parts: &[&[u8]]) -> Check<Digest> {
        let len = 32 + parts.iter().map(|p| p.len()).sum::<usize>();
        let blocks = ((len + 9 + 63) / 64) as u64;
        if blocks > self.work.work_bound - self.work.compression_blocks {
            return Err(());
        }
        self.work.compression_blocks += blocks;
        self.work.hash_calls += 1;
        // Every transaction-verification hash fits this stack buffer. The
        // native vector replay additionally supports long upstream messages.
        let mut stack = [0u8; 352];
        let mut large;
        let bytes = if 64 + len <= stack.len() {
            &mut stack[..64 + len]
        } else {
            large = vec![0u8; 64 + len];
            large.as_mut_slice()
        };
        bytes[..16].copy_from_slice(&self.key[..16]);
        for (value, offset) in addr.iter().zip([64, 76, 80, 84, 88, 92]) {
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        let mut offset = 96;
        for part in parts {
            bytes[offset..offset + part.len()].copy_from_slice(part);
            offset += part.len();
        }
        Ok((self.hash)(bytes))
    }
    fn h(&mut self, addr: [u32; 6], parts: &[&[u8]]) -> Check<Node> {
        Ok(self.full(addr, parts)?[..16].try_into().unwrap())
    }
    fn wots(
        &mut self,
        sig: &[u8],
        message: &[u8],
        stateful: bool,
        kp: u32,
        layer: u32,
        tree: u32,
    ) -> Check<Node> {
        self.work.wots_attempts += 1;
        let root: Node = self.key[16..].try_into().unwrap();
        let digest = if stateful {
            self.h([layer, tree, 4, 0, 0, 0], &[&sig[..32], &root, message])?
        } else {
            message.try_into().map_err(|_| ())?
        };
        let digits = self.h(
            [layer, tree, if stateful { 3 } else { 14 }, kp, 0, 0],
            &[&digest, &sig[32..36]],
        )?;
        if digits.iter().map(|d| u32::from(*d)).sum::<u32>() != 2040 {
            return Err(());
        }
        let mut tips = [0u8; 256];
        for chain in 0..16 {
            let mut node: Node = sig[36 + chain * 16..52 + chain * 16].try_into().unwrap();
            for step in u32::from(digits[chain])..255 {
                node = self.h(
                    [
                        layer,
                        tree,
                        if stateful { 0 } else { 11 },
                        kp,
                        chain as u32,
                        step,
                    ],
                    &[&node],
                )?;
            }
            tips[chain * 16..(chain + 1) * 16].copy_from_slice(&node);
        }
        self.h(
            [layer, tree, if stateful { 1 } else { 12 }, kp, 0, 0],
            &[&tips],
        )
    }
    fn compact_candidate(&mut self, message: &[u8], sig: &[u8], candidate: u32) -> Check<bool> {
        let q = ((sig.len() - 308) / 16) as u32;
        let mut node = self.wots(&sig[16..308], message, true, candidate, 0, 0)?;
        for i in 0..q {
            let sibling = &sig[308 + i as usize * 16..324 + i as usize * 16];
            let height = if candidate <= 210 {
                211 - candidate + i
            } else {
                i + 1
            };
            node = if candidate <= 210 && i == 0 {
                self.h([0, 0, 2, 0, height, 0], &[&node, sibling])?
            } else {
                self.h([0, 0, 2, 0, height, 0], &[sibling, &node])?
            };
        }
        Ok(self.h([0, 0, 17, 0, 0, 0], &[&node, &sig[..16]])? == self.key[16..])
    }
    fn compact(&mut self, message: &[u8], sig: &[u8]) -> Check<bool> {
        let q = ((sig.len() - 308) / 16) as u32;
        for candidate in q..=if q == 210 { 211 } else { q } {
            if self
                .compact_candidate(message, sig, candidate)
                .unwrap_or(false)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn indices(&mut self, digest: &Digest) -> Check<(Vec<u32>, u32)> {
        let mut selected = BTreeSet::new();
        let mut prefix = [0u8; 64];
        for counter in 0u32..64 {
            let block = self.full([0, 0, 10, 0, 0, 0], &[digest, &counter.to_be_bytes()])?;
            self.work.xof_blocks += 1;
            if counter < 2 {
                prefix[counter as usize * 32..(counter as usize + 1) * 32].copy_from_slice(&block);
            }
            for i in 0..15 {
                if selected.len() == 11 {
                    break;
                }
                let value = bits(&block, i * 17, 17);
                if value < 109571 {
                    selected.insert(value);
                }
            }
            if selected.len() == 11 && counter >= 2 {
                return Ok((selected.into_iter().collect(), bits(&prefix, 424, 32)));
            }
        }
        Err(())
    }
    fn pors(&mut self, sig: &[u8], indices: &[u32], tree: u32) -> Check<Node> {
        let mut nodes = BTreeMap::new();
        for (i, &index) in indices.iter().enumerate() {
            let position = if index < 88070 {
                (0, index)
            } else {
                (1, index - 44035)
            };
            nodes.insert(
                position,
                self.h([0, tree, 6, 0, 0, index], &[&sig[32 + i * 16..48 + i * 16]])?,
            );
        }
        let mut cursor = 208;
        for level in 0..17 {
            let current: Vec<_> = nodes.keys().filter(|p| p.0 == level).map(|p| p.1).collect();
            for index in current {
                let Some(node) = nodes.remove(&(level, index)) else {
                    continue;
                };
                let sibling = if let Some(sibling) = nodes.remove(&(level, index ^ 1)) {
                    sibling
                } else {
                    if cursor + 16 > sig.len() {
                        return Err(());
                    }
                    let sibling = sig[cursor..cursor + 16].try_into().unwrap();
                    cursor += 16;
                    self.work.pors_auth_nodes += 1;
                    sibling
                };
                let addr = [0, tree, 7, 0, level + 1, index / 2];
                let parent = if index % 2 == 0 {
                    self.h(addr, &[&node, &sibling])?
                } else {
                    self.h(addr, &[&sibling, &node])?
                };
                if nodes.insert((level + 1, index / 2), parent).is_some() {
                    return Err(());
                }
            }
            if nodes.len() == 1 && nodes.contains_key(&(level + 1, 0)) {
                self.work.pors_root_height = level + 1;
                break;
            }
        }
        if self.work.pors_root_height == 0 || sig[cursor..].iter().any(|b| *b != 0) {
            return Err(());
        }
        let node = *nodes.values().next().ok_or(())?;
        self.h([0, tree, 8, 0, 0, 0], &[&node])
    }
    fn recovery(&mut self, message: &[u8], sig: &[u8]) -> Check<bool> {
        let pors = &sig[16..2000];
        let root: Node = self.key[16..].try_into().unwrap();
        let digest = self.full([0, 0, 15, 0, 0, 0], &[&pors[..32], &root, message])?;
        let (indices, mut tree) = self.indices(&digest)?;
        let mut node = self.pors(pors, &indices, tree)?;
        for layer in 0..4 {
            let mut leaf = tree & 255;
            tree >>= 8;
            let xmss = &sig[2000 + layer * 420..2420 + layer * 420];
            node = self.wots(&xmss[..292], &node, false, leaf, layer as u32, tree)?;
            for height in 1..=8 {
                let sibling = &xmss[292 + (height - 1) * 16..308 + (height - 1) * 16];
                let right = leaf % 2 != 0;
                leaf >>= 1;
                let addr = [layer as u32, tree, 13, 0, height as u32, leaf];
                node = if right {
                    self.h(addr, &[sibling, &node])?
                } else {
                    self.h(addr, &[&node, sibling])?
                };
            }
        }
        Ok(self.h([0, 0, 17, 0, 0, 0], &[&sig[..16], &node])? == root)
    }
}

pub fn verify<F: FnMut(&[u8]) -> Digest>(auth: &Authorization, hash: F) -> Work {
    let bound = work_bound(auth.signature.len(), auth.message.len());
    if bound == 0 {
        return Work::default();
    }
    let mut v = Verifier {
        key: auth.key,
        hash,
        work: Work {
            compression_blocks: 1,
            work_bound: bound,
            ..Work::default()
        },
    };
    v.work.valid = if auth.signature.len() == 3680 {
        v.recovery(&auth.message, &auth.signature)
    } else {
        v.compact(&auth.message, &auth.signature)
    }
    .unwrap_or(false);
    v.work
}

#[cfg(feature = "native")]
pub fn native_hash(bytes: &[u8]) -> Digest {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}
