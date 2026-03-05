#!/bin/bash

# Script to convert Markdown to PDF using pandoc with mermaid support
# Usage: ./md_to_pdf.sh <markdown_file>

set -e  # Exit on error

# Check if filename is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <markdown_file>"
    echo "Example: $0 EECC_Enterprise_Wallet_Flyer_DE.md"
    exit 1
fi

filename="$1"

# Check if file exists
if [ ! -f "$filename" ]; then
    echo "Error: File '$filename' not found"
    exit 1
fi

# Extract filename without extension
filename_without_ending="${filename%.md}"

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if pandoc is installed
if ! command -v pandoc &> /dev/null; then
    echo "Error: pandoc is not installed"
    echo "Install with: sudo apt install pandoc"
    exit 1
fi

# Check if pandoc-mermaid-selenium-filter is installed
if [ ! -f "$HOME/.pandoc-venv/bin/pandoc-mermaid-selenium-filter" ]; then
    echo "Error: pandoc-mermaid-selenium-filter is not installed"
    echo "Install with: python3 -m venv ~/.pandoc-venv && ~/.pandoc-venv/bin/pip install pandoc-mermaid-selenium-filter"
    exit 1
fi

# Convert with mermaid support
echo "Converting ${filename} to PDF with mermaid support (using Selenium filter)..."

# Ensure DISPLAY is set for Chrome/Selenium (needed for headless mode)
if [ -z "$DISPLAY" ]; then
    echo "Warning: DISPLAY not set, setting to :0"
    export DISPLAY=:0
fi

# Convert with implicit_figures disabled to prevent image captions and floating
# Use pandoc-mermaid-selenium-filter for mermaid support
pandoc --from=markdown-implicit_figures \
  --filter "$HOME/.pandoc-venv/bin/pandoc-mermaid-selenium-filter" \
  --pdf-engine=xelatex \
  --columns=1000 \
  -o "${filename_without_ending}.pdf" \
  "${filename}"

echo "✓ PDF created: ${filename_without_ending}.pdf"
