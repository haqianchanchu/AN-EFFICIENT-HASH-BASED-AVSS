#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pip==24.3.1
python -m pip install -r requirements.txt
export PATH="$HOME/.cargo/bin:$PATH"
export RUSTUP_TOOLCHAIN=nightly-2023-12-01
rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal
python -m pip install --no-build-isolation ./vendor/pairing
python -m pip install --no-build-isolation -e .
python -m unittest discover -s tests -v
python examples/local_demo.py
