# RVMCA: RISC-V Machine Code Analyzer

This anonymous research artifact provides parsing, analysis, symbolic initial-state
synthesis, and instruction scheduling for RISC-V basic blocks.

## Requirements

- Python 3.11 or newer and the packages in `requirements.txt`.
- A RISC-V GNU/Linux compiler and objdump using the prefix
  `riscv64-unknown-linux-gnu-`.
- `qemu-riscv64` for local profiling.
- The profiling harness under `tools/pp`.

```bash
python -m pip install -r requirements.txt
make -C tools/pp
```

The `vex` directory contains the supplied backend source. If rebuilding pyvex,
use the supplied backend with the compatible pyvex source distribution. Backend
support varies by version; floating-point synthesis is currently incomplete.

## Usage

Generate initialization code and QEMU measurements from a JSON array:

```bash
bash run_pp.sh /path/to/blocks.json -o /path/to/blocks_pp.json
```

Run the generated blocks on a RISC-V board:

```bash
bash tools/pp/run_pp_hardware.sh /path/to/blocks_pp.json /path/to/results.json board
```

See [RUN_PP.md](RUN_PP.md) and the [hardware guide](tools/pp/RUN_PP_hardware.md)
for dependencies, field definitions, and resuming interrupted runs.

## Anonymous Review

Personal project attribution, private repository URLs, development paths, and
private board addresses have been redacted from the working files. Paths under
`/opt/artifact` and URLs under `example.invalid` are placeholders; configure
external datasets and board access for the local environment before running
archived experiments.

Third-party software retains its original license and attribution. Historical
checksums describe the original experiment files and do not authenticate their
redacted copies. Development Git metadata must be excluded from a review upload.
