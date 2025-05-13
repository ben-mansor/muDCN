#!/usr/bin/env python3
"""
Protocol Buffers compiler for the μDCN Control Plane.
This script compiles the .proto files into Python modules.
"""

import os
import sys
import subprocess
from pathlib import Path

def main():
    """Compile all .proto files in the proto directory."""
    
    # Get the root directory of the project
    root_dir = Path(__file__).parent.parent.absolute()
    
    # Proto file directory
    proto_dir = root_dir / "proto"
    
    # Output directory
    output_dir = Path(__file__).parent / "udcn_control" / "proto"
    
    # Create the output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Create an empty __init__.py file
    init_file = output_dir / "__init__.py"
    if not init_file.exists():
        with open(init_file, "w") as f:
            f.write("# Proto generated modules\n")
    
    # Find all .proto files
    proto_files = list(proto_dir.glob("*.proto"))
    
    if not proto_files:
        print(f"No .proto files found in {proto_dir}")
        return 1
    
    print(f"Found {len(proto_files)} .proto files")
    
    # Compile each proto file
    for proto_file in proto_files:
        print(f"Compiling {proto_file.name}...")
        
        # The command to compile the proto file
        cmd = [
            "python", "-m", "grpc_tools.protoc",
            f"--proto_path={proto_dir}",
            f"--python_out={output_dir}",
            f"--grpc_python_out={output_dir}",
            str(proto_file)
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error compiling {proto_file.name}:")
            print(result.stderr)
            return 1
    
    print("All proto files compiled successfully!")
    return 0

if __name__ == "__main__":
    sys.exit(main())
