//! A bounded receipt decoder/verifier and a narrow native transaction-checker ABI.
use anyhow::{ensure, Result};
use bincode::Options;
use risc0_zkvm::{sha::Digest, InnerReceipt, Receipt};

pub fn decode(bytes: &[u8], maximum: usize) -> Result<Receipt> {
    ensure!(!bytes.is_empty() && bytes.len() <= maximum, "receipt byte limit");
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding().with_limit(bytes.len() as u64)
        .reject_trailing_bytes().deserialize(bytes)?)
}

pub fn verify(receipt: &Receipt, image: [u8; 32], journal: [u8; 32]) -> Result<()> {
    match &receipt.inner {
        InnerReceipt::Composite(proof) => {
            ensure!(!proof.segments.is_empty() && proof.segments.len() <= 4096, "segment count limit");
            ensure!(proof.assumption_receipts.is_empty(), "assumption receipts are not permitted");
        }
        InnerReceipt::Succinct(_) => {},
        _ => anyhow::bail!("only STARK receipts are accepted"),
    }
    receipt.verify(Digest::from_bytes(image))?;
    ensure!(receipt.journal.bytes == journal, "different authorization claims");
    Ok(())
}

/// Return 1 only for a valid receipt for the caller's fixed program and claims.
/// Caller must supply valid byte ranges, with image and journal each 32 bytes.
/// The native transaction model limits the entire receipt to one block's weight.
#[no_mangle]
pub unsafe extern "C" fn btc_pq_receipt_verify(
    proof: *const u8, proof_len: usize, image: *const u8, journal: *const u8,
) -> i32 {
    if proof.is_null() || image.is_null() || journal.is_null() || proof_len == 0 || proof_len > 4_000_000 {
        return 0;
    }
    std::panic::catch_unwind(|| {
        let bytes = std::slice::from_raw_parts(proof, proof_len);
        let image: [u8; 32] = std::slice::from_raw_parts(image, 32).try_into().unwrap();
        let journal: [u8; 32] = std::slice::from_raw_parts(journal, 32).try_into().unwrap();
        decode(bytes, 4_000_000).and_then(|receipt| verify(&receipt, image, journal)).is_ok() as i32
    }).unwrap_or(0)
}
