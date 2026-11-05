# AN EFFICIENT HASH BASED AVSS

A research implementation of hash-based asynchronous verifiable secret sharing (BDECS-AVSS).
This project is derived from [GoSSamer](https://github.com/xxxsh1x1annva/GoSSamer).
It reuses and adapts GoSSamer polynomial arithmetic, hashing, reliable broadcast,
private delivery and NTL decoding components. The BDECS commitment, sharing and
recovery logic lives in `src/bdecs_avss`.

Development and documentation were completed with GPT assistance.

## Layout

- `src/bdecs_avss/`: main protocol and commitments.
- `src/GoSSamer/`, `src/adkg/`: shared upstream runtime components.
- `comparisons/protocols/`: GoSSamer ACSS/DPSS, SS24, hbACSS, Haven++ and LongLive.
- `comparisons/adkg_protocols/`: additional upstream protocol implementations.
- `vendor/pairing/`: Rust/Python field and pairing dependency, with original licenses.
- `examples/`: minimal executable sharing example.
- `tests/`: commitment and recovery correctness tests, not performance experiments.
- `scripts/`: environment setup.

Experimental datasets, cloud inventories, benchmark runners, fault injection,
plots, historical results, virtual environments and compiled binaries are excluded.

## Build

Use Ubuntu 20.04 / WSL2 with Python 3.8 and Rust nightly-2023-12-01.
Native Windows builds are not supported. Install system prerequisites:

```bash
sudo apt-get update
sudo apt-get install build-essential python3-venv python3-dev libntl-dev libgmp-dev libssl-dev pkg-config
```

Install rustup from https://rustup.rs/ if necessary. From the repository root:

```bash
bash scripts/setup.sh
source .venv/bin/activate
```

The script installs pinned Python dependencies, builds the vendored Rust extension,
builds the NTL C++ extension, installs this project and runs the checks below.
The Cargo lockfile is retained for the historical Rust toolchain.

## Run

```bash
python examples/local_demo.py
python -m unittest discover -s tests -v
```

The example runs four parties (threshold one) in one asyncio process, shares
`[17, 29]`, reconstructs the values, and checks they match. Expected final output:

```text
PASS: four parties shared and reconstructed [17, 29]
```

This is an in-memory functional example, not a network deployment or benchmark.
Applications supply authenticated `send`/`recv` callbacks to `AVSS`, consume
`output_queue`, and cancel the service and call `close()` when finished.
The legacy transport uses Python pickle: do not expose it to untrusted peers.
Functional tests do not establish a complete security proof or production readiness.
Comparison implementations are retained as source references; the example exercises
BDECS-AVSS only.

## Attribution and licensing

Original contributions are provided under the [MIT License](LICENSE), within the
scope specified there. Inherited and adapted GoSSamer code has unconfirmed upstream
licensing and is not relicensed by this project. This is a local release draft.
See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and
[LICENSE_STATUS.md](LICENSE_STATUS.md) for provenance and license status.


