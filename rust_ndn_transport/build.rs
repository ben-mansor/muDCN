fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile the protocol buffer definitions
    tonic_build::compile_protos("../proto/udcn.proto")?;
    Ok(())
}
