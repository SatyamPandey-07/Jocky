fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = std::env::var("JOCKY_PROTO_DIR").unwrap_or_else(|_| "../schemas/proto".into());
    let proto = format!("{proto_dir}/jocky_agent.proto");
    println!("cargo:rerun-if-changed={proto}");
    println!("cargo:rerun-if-changed=../schemas/entities.json");
    tonic_build::configure()
        .build_server(false)
        .compile_protos(&[proto.as_str()], &[proto_dir.as_str()])?;
    Ok(())
}
