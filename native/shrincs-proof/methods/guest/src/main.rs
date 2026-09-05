#![no_main]
use risc0_zkvm::{
    guest::env,
    sha::{Impl, Sha256},
};
use shrincs_proof_common::{claims_bytes, verify, Batch};
risc0_zkvm::guest::entry!(main);

fn hash(bytes: &[u8]) -> [u8; 32] {
    Impl::hash_bytes(bytes).as_bytes().try_into().unwrap()
}

pub fn main() {
    let batch: Batch = env::read();
    let claims = claims_bytes(&batch).expect("invalid claim dimensions");
    for auth in &batch.authorizations {
        assert!(verify(auth, hash).valid, "invalid SHRINCS authorization");
    }
    env::commit_slice(&hash(&claims));
}
