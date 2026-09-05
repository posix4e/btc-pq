use anyhow::{ensure, Context, Result};
use btc_pq_receipt::{decode, verify};
use risc0_zkvm::{default_prover, InnerReceipt, ProverOpts};
use std::{fs, time::Instant};

fn digest(text: &str) -> Result<[u8; 32]> {
    hex::decode(text)?.try_into().map_err(|_| anyhow::anyhow!("digest must be 32 bytes"))
}

fn main() -> Result<()> {
    ensure!(std::env::var("RISC0_DEV_MODE").unwrap_or_default().is_empty(), "development receipts are disabled");
    let args: Vec<_> = std::env::args().collect();
    ensure!(args.len() >= 5, "usage: receipt-tool verify|compress input.bin image_id journal_digest [output.bin]");
    let bytes = fs::read(&args[2])?;
    let image = digest(&args[3])?;
    let journal = digest(&args[4])?;
    let receipt = decode(&bytes, 512 * 1024 * 1024)?;
    verify(&receipt, image, journal)?;
    let start = Instant::now();
    if args[1] == "compress" {
        let path = args.get(5).context("output receipt path required")?;
        let compressed = default_prover().compress(&ProverOpts::succinct(), &receipt)?;
        ensure!(matches!(compressed.inner, InnerReceipt::Succinct(_)), "expected a succinct STARK");
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        let verify_start = Instant::now();
        verify(&compressed, image, journal)?;
        let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;
        let output = bincode::serialize(&compressed)?;
        fs::write(path, &output)?;
        println!("{}", serde_json::json!({"input_bytes":bytes.len(), "receipt_bytes":output.len(), "compress_ms":elapsed, "verify_ms":verify_ms, "receipt_kind":"succinct-stark", "image_id":args[3], "claims_digest":args[4], "valid":true}));
    } else {
        ensure!(args[1] == "verify", "unsupported command");
        println!("{}", serde_json::json!({"valid":true, "receipt_bytes":bytes.len()}));
    }
    Ok(())
}
