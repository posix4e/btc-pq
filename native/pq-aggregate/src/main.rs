//! Public-fixture bridge: transaction digests are supplied by the Python harness.
use rand::{SeedableRng, rngs::StdRng};
use rec_aggregation::{AggregateSignature, WireKeys, aggregate};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{env, fs, time::Instant};

#[derive(Serialize, Deserialize)]
struct Claim { epoch: u32, public_key: String, message: String }

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn unhex<const N: usize>(s: &str) -> Result<[u8; N], String> {
    if s.len() != N*2 || !s.is_ascii() { return Err("hex length".into()); }
    let mut bytes = [0u8; N];
    for i in 0..N { bytes[i] = u8::from_str_radix(&s[i*2..i*2+2], 16).map_err(|e| e.to_string())?; }
    Ok(bytes)
}
fn pair(epoch: u32, batch: u32) -> (xmss::XmssSecretKey, xmss::XmssPublicKey) {
    let mut seed = [0x42u8; 32]; // Public deterministic experiment material.
    seed[..4].copy_from_slice(&epoch.to_le_bytes());
    seed[4..8].copy_from_slice(&batch.to_le_bytes()); // Distinct keys for each batch size.
    xmss::key_gen_from_seed(seed, epoch, epoch).expect("one-epoch test key")
}
fn claims(path: &str) -> Result<(Vec<Claim>, WireKeys), String> {
    let claims: Vec<Claim> = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    if claims.is_empty() || claims.len() > 1024 { return Err("claim count".into()); }
    let mut groups = Vec::new();
    for (i, claim) in claims.iter().enumerate() {
        // Epochs serve only as fixture positions; each input has a distinct key.
        if claim.epoch != i as u32 { return Err("ordered fixture epochs required".into()); }
        let key: [u8; 32] = unhex(&claim.public_key)?;
        let pk = xmss::XmssPublicKey { merkle_root: key[..16].try_into().unwrap(), public_param: key[16..].try_into().unwrap() };
        groups.push((claim.epoch, unhex(&claim.message)?, vec![pk]));
    }
    Ok((claims, (groups, vec![])))
}

fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() < 3 { return Err("keys count | prove claims.json proof.bin | verify claims.json proof.bin".into()); }
    if args[1] == "keys" {
        let count: u32 = args[2].parse().map_err(|_| "count")?;
        if !(1..=1024).contains(&count) { return Err("count outside 1..1024".into()); }
        let keys: Vec<_> = (0..count).map(|epoch| json!({"epoch":epoch,"public_key":hex(&pair(epoch, count).1.flatten())})).collect();
        println!("{}", json!({"keys":keys}));
        return Ok(());
    }
    if args.len() != 4 { return Err("claims and proof paths required".into()); }
    let (records, keys) = claims(&args[2])?;
    if args[1] == "verify" {
        let bytes = fs::read(&args[3]).map_err(|e| e.to_string())?;
        let start = Instant::now();
        let valid = AggregateSignature::from_bytes_without_pubkeys(&bytes, keys)
            .and_then(|proof| proof.verify()).is_ok();
        println!("{}", json!({"valid":valid,"verify_seconds":start.elapsed().as_secs_f64()}));
        return Ok(());
    }
    if args[1] != "prove" { return Err("unknown command".into()); }
    lean_vm::init_prover();
    let start = Instant::now();
    let mut raw = Vec::new();
    for record in &records {
        let (sk, pk) = pair(record.epoch, records.len() as u32);
        if hex(&pk.flatten()) != record.public_key { return Err("key not from public fixture seed".into()); }
        let message = unhex(&record.message)?;
        // One signing call per one-epoch key in this public experiment.
        let signature = xmss::sign(&mut StdRng::seed_from_u64(record.epoch as u64), &sk, &message, record.epoch).map_err(|e| e.to_string())?;
        xmss::verify(&pk, &message, &signature, record.epoch).map_err(|e| format!("{e:?}"))?;
        raw.push((pk, record.epoch, message, signature));
    }
    let signing_seconds = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let proof = aggregate(&[], raw, vec![], None, 1).map_err(|e| format!("{e:?}"))?;
    let proving_seconds = start.elapsed().as_secs_f64();
    let start = Instant::now();
    proof.verify().map_err(|e| format!("{e:?}"))?;
    let verify_seconds = start.elapsed().as_secs_f64();
    if proof.xmss_signers() != keys.0 || !proof.sphincs_signers().is_empty() { return Err("proof signer set changed".into()); }
    let core = proof.to_bytes_without_pubkeys();
    fs::write(&args[3], &core).map_err(|e| e.to_string())?;
    println!("{}", json!({"valid":true,"inputs":records.len(),"raw_signature_bytes":records.len()*xmss::SIG_SIZE,
        "proof_bytes":core.len(),"proof_with_claims_bytes":proof.to_bytes().len(),"signing_seconds":signing_seconds,
        "cold_proving_seconds":proving_seconds,"verify_seconds":verify_seconds}));
    Ok(())
}
fn main() {
    if let Err(error) = run() { eprintln!("{error}"); std::process::exit(2); }
}
