#!/bin/bash
# set -e ensures the script stops if any command fails, which signals the GitHub Action
set -e

# create venv only if it doesn't exist
pip install uv --quiet
if [ ! -d "cyberprotect_env" ]; then
    echo "Creating new environment..."
    uv venv cyberprotect_env
fi

# activate venv depending on platform
if [ -d "cyberprotect_env/Scripts" ]; then
    source cyberprotect_env/Scripts/activate # Windows
else
    source cyberprotect_env/bin/activate    # Linux/macOS (GitHub Actions)
fi

# sync requirements
uv pip install -r requirements.txt

# run the pipeline
python src/main.py