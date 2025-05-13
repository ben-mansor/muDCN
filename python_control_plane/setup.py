from setuptools import setup, find_packages

setup(
    name="udcn-control-plane",
    version="0.1.0",
    description="Python Control Plane with ML-Orchestration for μDCN",
    author="μDCN Team",
    author_email="udcn@example.com",
    packages=find_packages(),
    install_requires=[
        "tensorflow==2.12.0",
        "tensorflow-lite==2.12.0",
        "numpy>=1.22.0",
        "prometheus-client>=0.16.0",
        "grpcio>=1.51.1",
        "grpcio-tools>=1.51.1",
        "protobuf>=4.22.1",
        "scikit-learn>=1.2.2",
        "pandas>=1.5.3",
        "flask>=2.2.3",
        "pyyaml>=6.0",
        "requests>=2.28.2",
        "pyroute2>=0.7.3",
        "networkx>=3.0",
        "matplotlib>=3.7.1",
    ],
    extras_require={
        "dev": [
            "pytest>=7.3.1",
            "black>=23.3.0",
            "isort>=5.12.0",
            "mypy>=1.2.0",
            "flake8>=6.0.0",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.9",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.9",
)
