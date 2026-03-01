#!/bin/bash
# Smart test runner for faster feedback

set -e

# Function to run specific test categories
run_tests() {
    local category="$1"
    echo "🧪 Running $category tests..."
    
    case "$category" in
        "fast")
            # Run only fast unit tests (skip integration tests) 
            cargo test --quiet --release --test '*_tests'
            ;;
        "integration")
            # Run integration tests
            cargo test --test 'integration_tests' --quiet --release
            ;;
        "hash")
            # Run hash-related tests
            cargo test hash --quiet --release
            ;;
        "crypto")
            # Run cryptography-related tests
            cargo test sign --quiet --release
            cargo test key --quiet --release
            ;;
        "all")
            # Run all tests
            cargo test --release
            ;;
        *)
            echo "❌ Unknown test category: $category"
            echo "Available categories: fast, integration, hash, crypto, all"
            exit 1
            ;;
    esac
}

# Parse command line arguments
CATEGORY="${1:-fast}"

echo "🚀 Running tests in category: $CATEGORY"
run_tests "$CATEGORY"

echo "✅ Tests completed successfully!"