use anyhow::{bail, ensure, Context, Result};
use bincode::Options;
use risc0_zkvm::{
    default_executor, default_prover, ExecutorEnv, InnerReceipt, ProverOpts, Receipt,
};
use shrincs_proof_common::{claims_bytes, native_hash, Batch};
use shrincs_proof_methods::{SHRINCS_GUEST_ELF, SHRINCS_GUEST_ID};
use std::{fs, time::Instant};

fn check(receipt: &Receipt, batch: &Batch) -> Result<f64> {
    // No pairing-based wrapper and no mock receipts. The image ID binds the
    // complete verifier program; the journal binds the ordered payment claims.
    ensure!(
        matches!(
            receipt.inner,
            InnerReceipt::Composite(_) | InnerReceipt::Succinct(_)
        ),
        "not a STARK receipt"
    );
    let expected =
        native_hash(&claims_bytes(batch).map_err(|_| anyhow::anyhow!("invalid claims"))?);
    let start = Instant::now();
    receipt.verify(SHRINCS_GUEST_ID)?;
    ensure!(
        receipt.journal.bytes == expected,
        "receipt is for different authorization claims"
    );
    Ok(start.elapsed().as_secs_f64() * 1000.0)
}

fn main() -> Result<()> {
    ensure!(
        std::env::var("RISC0_DEV_MODE")
            .unwrap_or_default()
            .is_empty(),
        "unset RISC0_DEV_MODE; this experiment requires real proofs"
    );
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() >= 3,
        "usage: btc-pq-shrincs-proof prove|execute|verify batch.json [receipt.bin]"
    );
    let batch: Batch = serde_json::from_slice(&fs::read(&args[2])?)?;
    let claims = claims_bytes(&batch).map_err(|_| anyhow::anyhow!("invalid claims"))?;
    let mut result = serde_json::json!({"image_id": hex::encode(bytemuck_id()), "authorizations": batch.authorizations.len(), "claims_digest": hex::encode(native_hash(&claims)), "raw_signature_bytes": batch.authorizations.iter().map(|a| a.signature.len()).sum::<usize>()});
    match args[1].as_str() {
        "execute" | "prove" | "prove-succinct" => {
            let env = ExecutorEnv::builder()
                .write(&batch)?
                .segment_limit_po2(20)
                .session_limit(Some(1 << 31))
                .build()?;
            let start = Instant::now();
            if args[1] == "execute" {
                let session = default_executor().execute(env, SHRINCS_GUEST_ELF)?;
                ensure!(
                    session.journal.bytes == native_hash(&claims),
                    "execution journal mismatch"
                );
                result["execution_ms"] = (start.elapsed().as_secs_f64() * 1000.0).into();
                result["segments"] = session.segments.len().into();
                result["user_cycles"] = session.cycles().into();
                result["proved"] = false.into();
            } else {
                let path = args.get(3).context("receipt output path required")?;
                let opts = if args[1] == "prove-succinct" {
                    ProverOpts::succinct()
                } else {
                    ProverOpts::composite()
                };
                let info = default_prover().prove_with_opts(env, SHRINCS_GUEST_ELF, &opts)?;
                result["prove_ms"] = (start.elapsed().as_secs_f64() * 1000.0).into();
                result["stats"] = serde_json::to_value(&info.stats)?;
                result["verify_ms"] = check(&info.receipt, &batch)?.into();
                let bytes = bincode::serialize(&info.receipt)?;
                result["receipt_bytes"] = bytes.len().into();
                result["receipt_kind"] = match info.receipt.inner {
                    InnerReceipt::Composite(_) => "composite-stark",
                    _ => "succinct-stark",
                }
                .into();
                fs::write(path, bytes)?;
                result["proved"] = true.into();
            }
        }
        "verify" => {
            let bytes = fs::read(args.get(3).context("receipt path required")?)?;
            let decoded: Result<Receipt, _> = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .reject_trailing_bytes()
                .deserialize(&bytes);
            result["receipt_bytes"] = bytes.len().into();
            match decoded
                .map_err(anyhow::Error::from)
                .and_then(|receipt| check(&receipt, &batch))
            {
                Ok(ms) => {
                    result["verify_ms"] = ms.into();
                    result["valid"] = true.into();
                }
                Err(error) => {
                    result["valid"] = false.into();
                    result["error"] = error.to_string().into();
                }
            }
        }
        _ => bail!("unknown command"),
    }
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn bytemuck_id() -> Vec<u8> {
    SHRINCS_GUEST_ID
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect()
}
