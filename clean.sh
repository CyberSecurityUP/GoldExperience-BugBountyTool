#!/bin/bash
# =============================================================================
# ReconTool - Cleanup Script (SAFE VERSION)
# =============================================================================
# Removes ONLY scan outputs (recon/, logs). Does NOT touch source code.
# Usage: ./clean.sh
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "  ReconTool - Clean Scan Outputs"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ===== ONLY REMOVE SCAN OUTPUTS =====
echo -e "${YELLOW}Removing scan output directories...${NC}"

# Main recon output directory
if [ -d "recon" ]; then
    rm -rf recon
    echo -e "${GREEN}[REMOVED]${NC} recon/"
fi

# Alternative output directory names
for dir in output results scans; do
    if [ -d "$dir" ]; then
        rm -rf "$dir"
        echo -e "${GREEN}[REMOVED]${NC} $dir/"
    fi
done

# ===== REMOVE LOG FILES =====
echo ""
echo -e "${YELLOW}Removing log files...${NC}"

if [ -f "install_tools.log" ]; then
    rm -f install_tools.log
    echo -e "${GREEN}[REMOVED]${NC} install_tools.log"
fi

# Remove only log files, not directories
find . -maxdepth 2 -type f -name "*.log" -delete 2>/dev/null && \
    echo -e "${GREEN}[REMOVED]${NC} *.log files" || true

# ===== REMOVE PYTHON CACHE (safe) =====
echo ""
echo -e "${YELLOW}Removing Python cache...${NC}"
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
echo -e "${GREEN}[REMOVED]${NC} __pycache__ and *.pyc"

# ===== REMOVE OS JUNK =====
find . -type f -name ".DS_Store" -delete 2>/dev/null || true
find . -type f -name "Thumbs.db" -delete 2>/dev/null || true

echo ""
echo "=========================================="
echo -e "${GREEN}Done!${NC} Scan outputs removed."
echo "=========================================="
echo ""
echo "Source code preserved:"
echo "  - recontool/     (Python package)"
echo "  - config/        (Configuration)"
echo "  - recon.py       (CLI entry point)"
echo "  - install_tools.sh"
echo ""
