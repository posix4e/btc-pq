use shrincs_proof_common::{native_hash, verify, Authorization};
fn main() {
    let input: Vec<Authorization> = serde_json::from_reader(std::io::stdin()).unwrap();
    let result: Vec<_> = input.iter().map(|auth| verify(auth, native_hash)).collect();
    serde_json::to_writer(std::io::stdout(), &result).unwrap();
}
