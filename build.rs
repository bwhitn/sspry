fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    println!("cargo:rerun-if-changed=proto/sspry/v1/sspry.proto");

    tonic_build::configure()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .build_client(true)
        .build_server(true)
        .compile_protos(&["proto/sspry/v1/sspry.proto"], &["proto"])?;

    Ok(())
}
