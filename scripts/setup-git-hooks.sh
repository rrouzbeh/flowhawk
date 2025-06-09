#!/bin/bash
#
# Setup script for FlowHawk git hooks
# This script configures git to use the project's custom hooks
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print success
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

# Function to print error
print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Function to print info
print_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

echo -e "${YELLOW}🔧 Setting up FlowHawk git hooks...${NC}"

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    print_error "Not in a git repository"
    exit 1
fi

# Check if hooks directory exists
if [ ! -d ".githooks" ]; then
    print_error ".githooks directory not found"
    exit 1
fi

# Configure git to use our custom hooks directory
print_info "Configuring git to use .githooks directory..."
if git config core.hooksPath .githooks; then
    print_success "Git hooks path configured"
else
    print_error "Failed to configure git hooks path"
    exit 1
fi

# Make all hooks executable
print_info "Making hooks executable..."
chmod +x .githooks/*

# Test if the pre-commit hook works
print_info "Testing pre-commit hook..."
if [ -x ".githooks/pre-commit" ]; then
    print_success "Pre-commit hook is executable"
else
    print_error "Pre-commit hook is not executable"
    exit 1
fi

print_success "Git hooks setup complete!"
echo ""
print_info "The following hooks are now active:"
for hook in .githooks/*; do
    if [ -x "$hook" ]; then
        echo "  - $(basename "$hook")"
    fi
done
echo ""
print_info "These hooks will run automatically on git operations."
print_info "To bypass hooks temporarily, use 'git commit --no-verify'"