# μDCN Makefile
# High-performance ML-orchestrated Data-Centric Networking Architecture

# Configuration
RUST_DIR := rust_ndn_transport
PYTHON_DIR := python_control_plane
EBPF_DIR := ebpf_xdp
DEPLOY_DIR := deployment
TESTBED_DIR := testbed
DOCS_DIR := docs

# Docker configuration
DOCKER_REGISTRY := udcn
RUST_IMAGE := $(DOCKER_REGISTRY)/transport:latest
PYTHON_IMAGE := $(DOCKER_REGISTRY)/control-plane:latest

# Kubernetes configuration
KUBE_NS := udcn

# Default target
.PHONY: all
all: build

# Build all components
.PHONY: build
build: build-rust build-python build-ebpf

# Clean all components
.PHONY: clean
clean: clean-rust clean-python clean-ebpf
	@echo "Cleaned all components"

# Build Rust transport layer
.PHONY: build-rust
build-rust:
	@echo "Building Rust transport layer..."
	cd $(RUST_DIR) && cargo build --release
	@echo "Rust transport layer built successfully"

# Clean Rust transport layer
.PHONY: clean-rust
clean-rust:
	@echo "Cleaning Rust transport layer..."
	cd $(RUST_DIR) && cargo clean
	@echo "Rust transport layer cleaned successfully"

# Build Python control plane
.PHONY: build-python
build-python:
	@echo "Building Python control plane..."
	cd $(PYTHON_DIR) && pip install -e .
	@echo "Python control plane built successfully"

# Clean Python control plane
.PHONY: clean-python
clean-python:
	@echo "Cleaning Python control plane..."
	cd $(PYTHON_DIR) && rm -rf *.egg-info build dist __pycache__
	@echo "Python control plane cleaned successfully"

# Build eBPF/XDP components
.PHONY: build-ebpf
build-ebpf:
	@echo "Building eBPF/XDP components..."
	cd $(EBPF_DIR) && make
	@echo "eBPF/XDP components built successfully"

# Clean eBPF/XDP components
.PHONY: clean-ebpf
clean-ebpf:
	@echo "Cleaning eBPF/XDP components..."
	cd $(EBPF_DIR) && make clean
	@echo "eBPF/XDP components cleaned successfully"

# Train ML model
.PHONY: train-model
train-model:
	@echo "Training ML model..."
	cd $(PYTHON_DIR) && python -m udcn_control.model_trainer --output models/mtu_predictor.tflite
	@echo "ML model trained successfully"

# Build Docker images
.PHONY: docker-build
docker-build: docker-build-rust docker-build-python

# Build Rust Docker image
.PHONY: docker-build-rust
docker-build-rust:
	@echo "Building Rust Docker image..."
	docker build -t $(RUST_IMAGE) -f $(DEPLOY_DIR)/Dockerfile.rust .
	@echo "Rust Docker image built successfully"

# Build Python Docker image
.PHONY: docker-build-python
docker-build-python:
	@echo "Building Python Docker image..."
	docker build -t $(PYTHON_IMAGE) -f $(DEPLOY_DIR)/Dockerfile.python .
	@echo "Python Docker image built successfully"

# Push Docker images to registry
.PHONY: docker-push
docker-push:
	@echo "Pushing Docker images to registry..."
	docker push $(RUST_IMAGE)
	docker push $(PYTHON_IMAGE)
	@echo "Docker images pushed successfully"

# Deploy to Kubernetes
.PHONY: deploy
deploy:
	@echo "Deploying to Kubernetes..."
	kubectl create namespace $(KUBE_NS) --dry-run=client -o yaml | kubectl apply -f -
	kubectl apply -f $(DEPLOY_DIR)/kubernetes/udcn-transport.yaml -n $(KUBE_NS)
	kubectl apply -f $(DEPLOY_DIR)/kubernetes/udcn-control-plane.yaml -n $(KUBE_NS)
	kubectl apply -f $(DEPLOY_DIR)/kubernetes/prometheus.yaml -n $(KUBE_NS)
	@echo "Deployed to Kubernetes successfully"

# Delete deployment from Kubernetes
.PHONY: undeploy
undeploy:
	@echo "Removing deployment from Kubernetes..."
	kubectl delete -f $(DEPLOY_DIR)/kubernetes/udcn-transport.yaml -n $(KUBE_NS) --ignore-not-found
	kubectl delete -f $(DEPLOY_DIR)/kubernetes/udcn-control-plane.yaml -n $(KUBE_NS) --ignore-not-found
	kubectl delete -f $(DEPLOY_DIR)/kubernetes/prometheus.yaml -n $(KUBE_NS) --ignore-not-found
	@echo "Deployment removed from Kubernetes successfully"

# Run tests
.PHONY: test
test: test-rust test-python test-integration

# Run Rust tests
.PHONY: test-rust
test-rust:
	@echo "Running Rust tests..."
	cd $(RUST_DIR) && cargo test
	@echo "Rust tests completed"

# Run Python tests
.PHONY: test-python
test-python:
	@echo "Running Python tests..."
	cd $(PYTHON_DIR) && python -m pytest
	@echo "Python tests completed"

# Run integration tests
.PHONY: test-integration
test-integration:
	@echo "Running integration tests..."
	cd $(TESTBED_DIR) && python traffic_generator.py --config traffic_config.yaml
	@echo "Integration tests completed"

# Generate documentation
.PHONY: docs
docs:
	@echo "Generating documentation..."
	cd $(RUST_DIR) && cargo doc --no-deps
	cd $(PYTHON_DIR) && sphinx-build -b html docs/source docs/build
	@echo "Documentation generated successfully"

# Help target
.PHONY: help
help:
	@echo "μDCN Makefile Help"
	@echo "=================="
	@echo "make               Build all components"
	@echo "make build         Build all components"
	@echo "make clean         Clean all components"
	@echo "make build-rust    Build Rust transport layer"
	@echo "make build-python  Build Python control plane"
	@echo "make build-ebpf    Build eBPF/XDP components"
	@echo "make train-model   Train ML model"
	@echo "make docker-build  Build Docker images"
	@echo "make docker-push   Push Docker images to registry"
	@echo "make deploy        Deploy to Kubernetes"
	@echo "make undeploy      Remove deployment from Kubernetes"
	@echo "make test          Run all tests"
	@echo "make docs          Generate documentation"
	@echo "make help          Show this help message"
