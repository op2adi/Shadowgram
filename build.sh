#!/usr/bin/env bash
# Shadowgram Build Script
# Automates common build, test, and development tasks

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prereqs() {
    info "Checking prerequisites..."

    # Check Rust
    if ! command -v cargo &> /dev/null; then
        error "Rust/Cargo not found. Install rustup: https://rustup.rs/"
        exit 1
    fi
    success "Rust: $(rustc --version)"

    # Check Node.js (for Tauri)
    if command -v node &> /dev/null; then
        success "Node.js: $(node --version)"
    else
        warn "Node.js not found. Tauri builds will fail."
    fi

    # Check npm (for Tauri)
    if command -v npm &> /dev/null; then
        success "npm: $(npm --version)"
    else
        warn "npm not found. Tauri builds will fail."
    fi
}

# Build all crates
build() {
    info "Building Shadowgram..."
    cargo build --release "$@"
    success "Build complete!"
}

# Build in debug mode
build_debug() {
    info "Building Shadowgram (debug)..."
    cargo build "$@"
    success "Debug build complete!"
}

# Run all tests
test() {
    info "Running tests..."
    cargo test --release "$@"
    success "All tests passed!"
}

# Run tests with coverage (requires cargo-tarpaulin)
coverage() {
    info "Running tests with coverage..."

    if ! command -v cargo-tarpaulin &> /dev/null; then
        error "cargo-tarpaulin not found. Install with: cargo install cargo-tarpaulin"
        exit 1
    fi

    cargo tarpaulin --out html --output-dir coverage
    success "Coverage report generated in coverage/"
}

# Run clippy lints
lint() {
    info "Running clippy..."
    cargo clippy --all-targets -- -D warnings
    success "No lints found!"
}

# Format code
fmt() {
    info "Formatting code..."
    cargo fmt --all
    success "Code formatted!"
}

# Check format
fmt_check() {
    info "Checking code format..."
    cargo fmt --all -- --check
    success "Code is formatted!"
}

# Generate documentation
docs() {
    info "Generating documentation..."
    cargo doc --no-deps --open
    success "Documentation generated!"
}

# Build Tauri frontend
build_tauri() {
    info "Building Tauri frontend..."

    if ! command -v npm &> /dev/null; then
        error "npm not found. Install Node.js first."
        exit 1
    fi

    cd src-tauri
    npm install
    npm run build
    cd ..

    info "Building Tauri app..."
    cargo tauri build

    success "Tauri app built!"
}

# Run Tauri dev server
dev() {
    info "Starting Tauri dev mode..."
    cargo tauri dev "$@"
}

# Run specific test
test_specific() {
    if [ -z "$1" ]; then
        error "Test name required. Usage: $0 test_specific <test_name>"
        exit 1
    fi

    info "Running test: $1"
    cargo test "$1" --release -- --nocapture
}

# Clean build artifacts
clean() {
    info "Cleaning build artifacts..."
    cargo clean
    rm -rf target/
    rm -rf src-tauri/target/
    rm -rf node_modules/
    rm -rf src/
    success "Clean complete!"
}

# Show help
help() {
    echo "Shadowgram Build Script"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  check       Check prerequisites"
    echo "  build       Build release"
    echo "  debug       Build debug"
    echo "  test        Run all tests"
    echo "  coverage    Run tests with coverage"
    echo "  lint        Run clippy lints"
    echo "  fmt         Format code"
    echo "  fmt-check   Check code format"
    echo "  docs        Generate documentation"
    echo "  tauri       Build Tauri app"
    echo "  dev         Run Tauri dev mode"
    echo "  test-one    Run specific test (requires test name)"
    echo "  clean       Clean build artifacts"
    echo "  help        Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 check"
    echo "  $0 build"
    echo "  $0 test -- --nocapture"
    echo "  $0 test-one test_complete_message_flow"
    echo ""
}

# Main entry point
main() {
    case "$1" in
        check)
            check_prereqs
            ;;
        build)
            shift
            build "$@"
            ;;
        debug)
            shift
            build_debug "$@"
            ;;
        test)
            shift
            test "$@"
            ;;
        coverage)
            coverage
            ;;
        lint)
            lint
            ;;
        fmt)
            fmt
            ;;
        fmt-check)
            fmt_check
            ;;
        docs)
            docs
            ;;
        tauri)
            build_tauri
            ;;
        dev)
            shift
            dev "$@"
            ;;
        test-one)
            shift
            test_specific "$@"
            ;;
        clean)
            clean
            ;;
        help|--help|-h)
            help
            ;;
        "")
            help
            ;;
        *)
            error "Unknown command: $1"
            echo ""
            help
            exit 1
            ;;
    esac
}

main "$@"