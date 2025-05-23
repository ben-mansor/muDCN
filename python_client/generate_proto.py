#!/usr/bin/env python3
"""
gRPC Python bindings generator for µDCN protocol

This script generates Python bindings from the udcn.proto file
using grpcio-tools. It creates the necessary Python modules for
interacting with the Rust gRPC server.
"""

import os
import sys
import shutil
import argparse
from grpc_tools import protoc

def main():
    """Generate Python bindings from proto file."""
    parser = argparse.ArgumentParser(description='Generate Python gRPC code from proto file')
    parser.add_argument('--proto-file', default='../proto/udcn.proto', 
                      help='Path to the proto file')
    parser.add_argument('--output-dir', default='../proto_gen/python',
                      help='Output directory for generated Python code')
    
    args = parser.parse_args()
    
    # Ensure output directory exists
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Get the directory of the proto file
    proto_dir = os.path.dirname(os.path.abspath(args.proto_file))
    
    # Generate Python code
    print(f"Generating Python gRPC code from {args.proto_file}...")
    protoc.main([
        'grpc_tools.protoc',
        f'--proto_path={proto_dir}',
        f'--python_out={args.output_dir}',
        f'--grpc_python_out={args.output_dir}',
        os.path.abspath(args.proto_file)
    ])
    
    print(f"Python bindings generated successfully in {args.output_dir}")
    print("\nTo use these bindings, first install the required dependencies:")
    print("pip install grpcio grpcio-tools")
    
    # Create an __init__.py file to make the directory a proper Python package
    with open(os.path.join(args.output_dir, '__init__.py'), 'w') as f:
        f.write("# Generated Python package for µDCN protocol\n")
    
    print("\nExample usage in Python:")
    print("```python")
    print("import sys")
    print(f"sys.path.append('{args.output_dir}')")
    print("import udcn_pb2")
    print("import udcn_pb2_grpc")
    print("```")

if __name__ == "__main__":
    main()
