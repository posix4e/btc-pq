fn main() {
    println!("cargo:rerun-if-env-changed=BTC_PQ_WRAPPER_SHA256");
    risc0_build::embed_methods();
}
