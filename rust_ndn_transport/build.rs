fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../proto/udcn.proto");
    println!("cargo:rerun-if-changed=proto/udcn.proto");
    
    // Compile proto files using tonic-build
    tonic_build::compile_protos("../proto/udcn.proto")?;
    
    // Fallback to local proto directory if the above path doesn't exist
    if std::fs::metadata("../proto/udcn.proto").is_err() {
        tonic_build::compile_protos("proto/udcn.proto")?;
    }
    
    Ok(())
}
