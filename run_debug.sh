#!/bin/bash

# Debug script for the smart contract analyzer pipeline
# Usage: ./run_debug.sh [debug_level]
# Debug levels: none, basic, ai, parse, analysis, verbose

set -e

DEBUG_LEVEL=${1:-"verbose"}

echo "🔍 Running pipeline with debug level: $DEBUG_LEVEL"
echo "=================================================="

case $DEBUG_LEVEL in
    "none")
        echo "Running without debug output..."
        go run cmd/test_pipeline/main.go
        ;;
    "basic")
        echo "Running with basic debug output..."
        DEBUG=true go run cmd/test_pipeline/main.go
        ;;
    "ai")
        echo "Running with AI debug output..."
        DEBUG=ai go run cmd/test_pipeline/main.go
        ;;
    "parse")
        echo "Running with parsing debug output..."
        DEBUG=parse go run cmd/test_pipeline/main.go
        ;;
    "analysis")
        echo "Running with analysis debug output..."
        DEBUG=analysis go run cmd/test_pipeline/main.go
        ;;
    "verbose")
        echo "Running with verbose debug output..."
        DEBUG=verbose go run cmd/test_pipeline/main.go
        ;;
    *)
        echo "Invalid debug level: $DEBUG_LEVEL"
        echo "Valid levels: none, basic, ai, parse, analysis, verbose"
        exit 1
        ;;
esac

echo ""
echo "✅ Pipeline completed with debug level: $DEBUG_LEVEL" 