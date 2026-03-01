#!/bin/bash
# Performance monitoring script

set -e

echo "📊 Running performance benchmarks..."

# Ensure we're using the latest release build
cargo build --release

echo "🔥 Running Criterion benchmarks..."
cargo bench --bench performance

echo "📈 Benchmark results saved to target/criterion/"
echo "💡 Open target/criterion/report/index.html to view detailed reports"

# Optional: Open benchmark report in browser
if command -v firefox &> /dev/null; then
    echo "🌐 Opening benchmark report in Firefox..."
    firefox target/criterion/report/index.html &
elif command -v chrome &> /dev/null; then
    echo "🌐 Opening benchmark report in Chrome..."
    chrome target/criterion/report/index.html &
fi