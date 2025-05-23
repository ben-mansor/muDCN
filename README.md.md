# μDCN Repository Usage Guide

This document provides comprehensive instructions for working with the μDCN GitHub repository. Whether you're a first-time user, contributor, or maintainer, you'll find detailed information on how to interact with this codebase effectively.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Repository Structure](#repository-structure)
3. [Development Workflow](#development-workflow)
4. [Contributing Changes](#contributing-changes)
5. [Issue Management](#issue-management)
6. [Release Process](#release-process)
7. [CI/CD Pipeline](#cicd-pipeline)
8. [Advanced Git Operations](#advanced-git-operations)

## Getting Started

### Cloning the Repository

```bash
# Basic clone
git clone https://github.com/yourusername/udcn.git

# Clone with submodules (recommended)
git clone --recursive https://github.com/yourusername/udcn.git

# If you already cloned without --recursive
cd udcn
git submodule update --init --recursive
```

### Setting Up Your Environment

1. **Install Dependencies**:
   ```bash
   # Install Docker and Docker Compose
   ./install_docker.sh

   # Install development tools
   sudo apt update
   sudo apt install -y build-essential clang llvm libelf-dev linux-headers-$(uname -r)
   ```

2. **Environment Verification**:
   ```bash
   # Verify Docker installation
   docker --version
   docker-compose --version

   # Verify kernel compatibility for eBPF/XDP
   uname -r  # Should be 5.x or newer for best compatibility
   ```

## Repository Structure

The repository follows this structure (see `directory_map.md` for complete details):

```
udcn/
├── docker/                  # Docker configuration files
├── ebpf_ndn/                # eBPF/NDN implementation
├── ebpf_xdp/                # XDP program implementation
├── rust_ndn_transport/      # Rust transport layer
├── python_control_plane/    # ML control plane
├── k8s/                     # Kubernetes configurations
├── docs/                    # Documentation
├── results/                 # Benchmark results
└── visualization_plots/     # Data visualization tools
```

### Branch Organization

The repository is organized into several branches:

- **`main`**: Production-ready code, stable and tested
- **`develop`**: Integration branch for new features
- **`kubernetes`**: Experimental Kubernetes deployment
- **`feature/*`**: Individual feature branches

## Development Workflow

### Creating a New Feature

```bash
# Start from the develop branch
git checkout develop
git pull origin develop

# Create a feature branch
git checkout -b feature/your-feature-name

# Make your changes...

# Commit your changes
git add .
git commit -m "Add feature X"

# Push to GitHub
git push -u origin feature/your-feature-name
```

### Running the Test Suite

```bash
# Run the full test suite
make test

# Run specific tests
make test-transport
make test-control
```

### Local Testing with Docker

```bash
# Build and run with Docker Compose
docker-compose up --build

# Run in detached mode
docker-compose up -d

# View logs
docker-compose logs -f

# Tear down
docker-compose down
```

## Contributing Changes

### Pull Request Process

1. **Fork the Repository** (if you're not a direct contributor)
2. **Create a Feature Branch** as described above
3. **Make Your Changes** following the coding standards
4. **Test Your Changes** using the test suite
5. **Submit a Pull Request** against the `develop` branch
6. **Address Review Feedback** if requested

### Code Standards

- **Rust Code**: Follow [Rust style guidelines](https://doc.rust-lang.org/1.0.0/style/README.html)
- **Python Code**: Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- **C/eBPF Code**: Follow [Linux kernel coding style](https://www.kernel.org/doc/html/v4.10/process/coding-style.html)
- **Documentation**: Use Markdown for documentation
- **Commit Messages**: Follow [conventional commits](https://www.conventionalcommits.org/) format

## Issue Management

### Creating Issues

1. Go to the [Issues](https://github.com/yourusername/udcn/issues) tab
2. Click "New Issue"
3. Select the appropriate template (Bug Report or Feature Request)
4. Fill out the required information

### Issue Labels

- **bug**: Something isn't working
- **enhancement**: New feature or request
- **documentation**: Documentation improvements
- **good first issue**: Good for newcomers
- **help wanted**: Extra attention is needed

## Release Process

### Version Naming

We use [Semantic Versioning](https://semver.org/):
- **MAJOR**: Incompatible API changes
- **MINOR**: Add functionality (backward-compatible)
- **PATCH**: Bug fixes (backward-compatible)

### Creating a Release

1. **Update Version Numbers**:
   - Update version in `Cargo.toml`, `setup.py`, etc.
   
2. **Create Release Branch**:
   ```bash
   git checkout develop
   git checkout -b release/vX.Y.Z
   ```

3. **Final Testing**:
   ```bash
   make test
   ```

4. **Merge to Main**:
   ```bash
   git checkout main
   git merge --no-ff release/vX.Y.Z
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin main --tags
   ```

5. **Create GitHub Release**:
   - Go to GitHub Releases
   - Create new release from tag
   - Include release notes

## CI/CD Pipeline

Our repository uses GitHub Actions for CI/CD:

- **Pull Request Checks**: Automatically run on every PR
- **Integration Tests**: Run when merging to develop
- **Deployment**: Triggered on tagged releases

### Viewing CI/CD Results

1. Go to the "Actions" tab in GitHub
2. Select the workflow run you're interested in
3. Review logs and artifacts

## Advanced Git Operations

### Keeping Your Fork Updated

```bash
# Add the upstream repository
git remote add upstream https://github.com/originalowner/udcn.git

# Fetch from upstream
git fetch upstream

# Update your local main branch
git checkout main
git merge upstream/main

# Update your local develop branch
git checkout develop
git merge upstream/develop
```

### Managing Large Files

For large result files or datasets:

```bash
# Use Git LFS for large files
git lfs track "*.csv"
git lfs track "*.json"
git add .gitattributes

# Commit and push
git add your-large-file.csv
git commit -m "Add dataset"
git push
```

### Useful Git Commands

```bash
# View branch history
git log --graph --oneline --decorate

# Stash changes temporarily
git stash
git stash pop

# Rebase your branch
git rebase -i develop

# Amend the last commit
git commit --amend
```

---

For additional help or questions about repository usage, please open an issue on GitHub or contact the maintainers directly.
