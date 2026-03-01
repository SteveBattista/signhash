#!/bin/bash
# Development build script for faster iteration

set -e

echo "🚀 Fast development build..."

# Use development profile for faster compilation
cargo build --profile dev-opt

echo "✅ Build complete! Running basic tests..."

# Run a subset of fast tests
cargo test --lib --quiet

echo "🎉 Ready for development!"