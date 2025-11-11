// Code generation for gRPC protobuf definitions

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(&["proto/hypr.proto"], &["proto"])?;
    Ok(())
}
