fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&simplicity_unchained_policy::manifest())
            .expect("manifest serialization")
    );
}
