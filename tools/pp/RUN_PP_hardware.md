# PP Hardware Measurement Guide

## Basic Usage

Run the script on the target RISC-V Linux board:

```bash
cd /path/to/pp
bash run_pp_hardware.sh non_fp_pp.json
```

The default output is `non_fp_pp.board.json`. Each record receives a `board` field containing the complete output from `pp`.

Specify an output file:

```bash
bash run_pp_hardware.sh non_fp_pp.json results.json
```

Specify a result field name, such as `starfive`:

```bash
bash run_pp_hardware.sh non_fp_pp.json results.json starfive
```

Alternatively, use `--key` or `-k`:

```bash
bash run_pp_hardware.sh non_fp_pp.json results.json --key starfive
```

Input and output must be different files. If the result field already exists, it is replaced and placed at the end of the object.

Show command-line help:

```bash
bash run_pp_hardware.sh --help
```

## Requirements

Copy the following files to the board:

```text
pp/
├── pp                    # Executable built for the target board
├── run_pp_hardware.sh
└── non_fp_pp.json         # Input containing pp_init and pp_code
```

Required commands:

- Bash
- jq 1.6 or newer
- GNU `timeout`, `sha256sum`, `mktemp`, `mkfifo`, `truncate`, `wc`, and `sync` with `-d` support
- Standard file utilities, including `cat`, `mkdir`, and `rm`

Python is not required. Make the measurement executable runnable:

```bash
chmod +x pp
```

By default, the script runs `pp` from its own directory, regardless of the current working directory. Set `PP_BIN` to use another executable.

## Input Format

The input must be a JSON array of objects with the following fields:

| Field | Requirement |
|---|---|
| `pp_init` | Initialization machine-code text; an empty string is allowed |
| `pp_code` | Nonempty machine-code text for the measured basic block |

Example:

```json
[
  {
    "id": "example:1",
    "pp_init": "00000513\taddi a0,zero,0",
    "pp_code": "00150513\taddi a0,a0,1"
  }
]
```

Each code line starts with a hexadecimal instruction encoding and may include disassembly text. Other record fields are preserved. The legacy fields `init_binary` and `block_binary` are also accepted; `pp_init` and `pp_code` take precedence when present.

## Output Format

For a successful execution, the added field contains the complete standard output from `pp`, including samples and the final `cycles` line:

```json
{
  "id": "example:1",
  "pp_init": "...",
  "pp_code": "...",
  "board": "\n[0]: 100 - 80\n...\ncycles: 6\n"
}
```

Other outcomes are recorded as strings with these prefixes:

| Prefix | Meaning |
|---|---|
| `SKIP:` | Missing or invalid initialization or basic-block code |
| `TIMEOUT:` | The per-record execution time limit was exceeded |
| `ERROR:` | `pp` exited with a nonzero code; its standard output and standard error are included |

When the program exits normally, its standard output is saved without requiring a `cycles` line.

## Timeouts and Batch Rest Periods

Configure execution through environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `PP_BIN` | `pp` in the script directory | Path to the board measurement executable |
| `PP_TIMEOUT` | `60` | Per-record timeout in seconds; must be positive |
| `BATCH_SIZE` | `100` | Newly processed records between rest periods; `0` disables resting |
| `REST_TIME` | `3` | Rest duration in seconds |

Allow five seconds per record and rest for three seconds after every 100 records:

```bash
PP_TIMEOUT=5 BATCH_SIZE=100 REST_TIME=3 \
  bash run_pp_hardware.sh non_fp_pp.json results.json board
```

Use another executable and disable batch rest periods:

```bash
PP_BIN=/path/to/pp BATCH_SIZE=0 \
  bash run_pp_hardware.sh non_fp_pp.json results.json board
```

## Streaming Output and Resuming

The script parses records incrementally with `jq --stream`. After each record completes, it writes and flushes the result to disk. Memory use depends primarily on the size of a single record.

During execution, the output contains completed records. Two checkpoint files are also created:

```text
results.json.progress.jsonl
results.json.progress.meta.json
```

After an interruption, keep both checkpoint files and rerun the same command:

```bash
bash run_pp_hardware.sh non_fp_pp.json results.json board
```

The script checks that the input contents, `pp` binary, and result field name match the checkpoint, then continues after the saved records. If interrupted during a write, it reconstructs the output from the checkpoint. Checkpoint files are removed when all records have been processed.

To discard saved progress and restart, add `--force`:

```bash
bash run_pp_hardware.sh non_fp_pp.json results.json board --force
```

`FORCE=1` is also supported. Once a run has completed and its checkpoints have been removed, running the command again remeasures all records and overwrites the output.
