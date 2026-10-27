#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: bash run_pp_hardware.sh INPUT.json [OUTPUT.json] [FIELD]
       bash run_pp_hardware.sh INPUT.json [OUTPUT.json] --key FIELD

Run native pp using each object's pp_init and pp_code strings.
Append complete pp stdout under FIELD (default: board).
Default output: INPUT_STEM.board.json. Input must be a JSON array.
Input and output must differ. Rerun the same command to resume progress.

Options: --key/-k FIELD, --force, --help/-h
Environment: PP_BIN, PP_TIMEOUT=60, BATCH_SIZE=100 (0 disables),
             REST_TIME=3, FORCE=1 (discard progress).
Dependencies: Bash, jq >= 1.6, timeout, sha256sum, standard Unix utilities.
EOF
}

positionals=()
field=board
force=${FORCE:-0}
while (( $# )); do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -k|--key)
            (( $# >= 2 )) || { echo 'Missing field name' >&2; exit 2; }
            field=$2; shift 2 ;;
        --force) force=1; shift ;;
        --) shift; positionals+=("$@"); break ;;
        -*) echo "Unknown option: $1" >&2; exit 2 ;;
        *) positionals+=("$1"); shift ;;
    esac
done
(( ${#positionals[@]} >= 1 && ${#positionals[@]} <= 3 )) || { usage >&2; exit 2; }
input=${positionals[0]}
output=${positionals[1]:-${input%.json}.board.json}
field=${positionals[2]:-$field}
case "$field" in
    ''|pp_init|pp_code|init_binary|block_binary|id|asm|binary|function|source_file|tags|pp_result)
        echo 'Choose a result field distinct from input fields' >&2; exit 2 ;;
esac
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
pp=${PP_BIN:-}
if [[ -z "$pp" ]]; then
    if [[ -x "$script_dir/pp" ]]; then pp="$script_dir/pp"; else pp="$script_dir/tools/pp/pp"; fi
fi
pp=$(command -v -- "$pp") || { echo 'Native pp not found; set PP_BIN' >&2; exit 1; }
[[ -x "$pp" ]] || { echo "pp is not executable: $pp" >&2; exit 1; }
for tool in jq timeout sha256sum mktemp mkfifo truncate wc sync; do
    command -v "$tool" >/dev/null || { echo "Missing command: $tool" >&2; exit 1; }
done
[[ -f "$input" ]] || { echo "Input not found: $input" >&2; exit 1; }
[[ ! "$input" -ef "$output" && "$input" != "$output" ]] || { echo 'Output must differ from input' >&2; exit 1; }
pp_timeout=${PP_TIMEOUT:-60}
batch_size=${BATCH_SIZE:-100}
rest_time=${REST_TIME:-3}
[[ "$pp_timeout" =~ ^[0-9]+([.][0-9]+)?$ && "$batch_size" =~ ^[0-9]+$ && "$rest_time" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
    echo 'Invalid PP_TIMEOUT, BATCH_SIZE or REST_TIME' >&2; exit 2;
}
jq -en --argjson t "$pp_timeout" '$t > 0' >/dev/null || { echo 'PP_TIMEOUT must be positive' >&2; exit 2; }
batch_size=$((10#$batch_size))

# fromstream reconstructs only one array item. Never use jq .[] or jq -s on
# the full dataset: both would retain the complete array in memory.
stream_records() {
    jq -cn --stream '
        fromstream(1 | truncate_stream(inputs |
            if (.[0] | length) == 0 then
                if .[1] == [] then empty else error("Input must be an array") end
            elif (.[0][0] | type) != "number" then error("Input must be an array")
            else . end)) |
        if type == "object" then . else error("Every item must be an object") end
    ' "$input"
}

# Streaming preflight catches malformed input before modifying output.
total=$(stream_records | wc -l)
mkdir -p -- "$(dirname -- "$output")"
progress="$output.progress.jsonl"
metadata="$output.progress.meta.json"
tmp_dir=$(mktemp -d)
producer=''
cleanup() {
    if [[ -n "$producer" ]]; then
        kill "$producer" 2>/dev/null || true
        wait "$producer" 2>/dev/null || true
    fi
    # Only this invocation's mktemp directory is removed.
    rm -r -- "$tmp_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
input_hash=$(sha256sum < "$input"); input_hash=${input_hash%% *}
pp_hash=$(sha256sum < "$pp"); pp_hash=${pp_hash%% *}
signature=$(jq -cn --arg input "$input_hash" --arg pp "$pp_hash" --arg key "$field" \
    '{input_sha256:$input,pp_sha256:$pp,key:$key}')
if [[ -e "$progress" || -e "$metadata" ]]; then
    if [[ "$force" == 1 ]]; then
        : > "$progress"
    elif [[ ! -f "$progress" || ! -f "$metadata" ]] || \
         ! jq -e --argjson expected "$signature" '. == $expected' "$metadata" >/dev/null; then
        echo 'Incompatible checkpoint; use --force to restart' >&2; exit 1
    fi
fi
printf '%s\n' "$signature" > "$metadata"
touch -- "$progress"

# Keep the output a valid JSON array after each completed record. The durable
# JSONL checkpoint can rebuild it if interrupted during a write.
printf '[\n]\n' > "$output"
output_size=4
completed=0
append_output() {
    local record_file=$1 size
    truncate -s "$((output_size - 2))" -- "$output"
    if (( completed > 0 )); then printf ',\n' >> "$output"; fi
    cat -- "$record_file" >> "$output"
    printf '\n]\n' >> "$output"
    size=$(wc -c < "$record_file")
    output_size=$((output_size - 2 + size + 3 + (completed > 0 ? 2 : 0)))
    sync -d "$output"
}
valid_bytes=0
while IFS= read -r item; do
    printf '%s\n' "$item" > "$tmp_dir/record"
    jq -e --arg key "$field" 'type == "object" and has($key)' "$tmp_dir/record" >/dev/null
    append_output "$tmp_dir/record"
    ((completed += 1))
    bytes=$(wc -c < "$tmp_dir/record")
    valid_bytes=$((valid_bytes + bytes))
done < "$progress"
# Drop a torn last checkpoint line; all committed records end with a newline.
truncate -s "$valid_bytes" -- "$progress"
(( completed <= total )) || { echo 'Checkpoint longer than input' >&2; exit 1; }
printf 'Input: %s\nOutput: %s\nField: %s\nResume: %d/%d\n' "$input" "$output" "$field" "$completed" "$total" >&2

# Escape bounded chunks without placing full pp output in a shell variable.
escape_file() {
    local chunk
    while IFS= read -r -N 4096 chunk || [[ -n "$chunk" ]]; do
        printf '%s' "$chunk" | jq -Rsj 'tojson | .[1:-1]'
    done < "$1"
}

mkfifo "$tmp_dir/records"
stream_records > "$tmp_dir/records" &
producer=$!
index=0
new_count=0
while IFS= read -r item; do
    ((index += 1))
    (( index > completed )) || continue
    printf '%s\n' "$item" > "$tmp_dir/item"
    object=$(jq -c --arg key "$field" 'del(.[$key])' "$tmp_dir/item")
    printf '%s' "${object%\}}" > "$tmp_dir/record"
    [[ "$object" == '{}' ]] || printf ',' >> "$tmp_dir/record"
    jq -jn --arg key "$field" '$key | tojson' >> "$tmp_dir/record"
    printf ':"' >> "$tmp_dir/record"
    status=ok
    if ! jq -e '
        (if has("pp_init") then .pp_init else .init_binary end | type) == "string" and
        (if has("pp_code") then .pp_code else .block_binary end |
            if type == "string" then test("\\S") else false end)
    ' "$tmp_dir/item" >/dev/null; then
        printf 'SKIP: missing pp_init or nonempty pp_code' >> "$tmp_dir/record"
        status=skipped
    else
        jq -r 'if has("pp_init") then .pp_init else .init_binary end' "$tmp_dir/item" > "$tmp_dir/block.init"
        jq -r 'if has("pp_code") then .pp_code else .block_binary end' "$tmp_dir/item" > "$tmp_dir/block.code"
        rc=0
        timeout --kill-after=1s "$pp_timeout" "$pp" "$tmp_dir/block.init" "$tmp_dir/block.code" \
            > "$tmp_dir/stdout" 2> "$tmp_dir/stderr" || rc=$?
        if (( rc == 124 || rc == 137 )); then
            printf 'TIMEOUT: pp exceeded %s seconds' "$pp_timeout" >> "$tmp_dir/record"
            status=timeout
        elif (( rc != 0 )); then
            printf 'ERROR: pp exited with code %d\n' "$rc" > "$tmp_dir/error"
            escape_file "$tmp_dir/error" >> "$tmp_dir/record"
            escape_file "$tmp_dir/stdout" >> "$tmp_dir/record"
            escape_file "$tmp_dir/stderr" >> "$tmp_dir/record"
            status=failed
        else
            escape_file "$tmp_dir/stdout" >> "$tmp_dir/record"
        fi
    fi
    printf '"}\n' >> "$tmp_dir/record"
    cat "$tmp_dir/record" >> "$progress"
    sync -d "$progress"
    append_output "$tmp_dir/record"
    ((completed += 1))
    ((new_count += 1))
    printf '[%d/%d] %s\n' "$index" "$total" "$status" >&2
    if (( batch_size > 0 && new_count % batch_size == 0 && index < total )); then
        sleep "$rest_time"
    fi
done < "$tmp_dir/records"
wait "$producer"
producer=''
(( completed == total )) || { echo 'Incomplete result count' >&2; exit 1; }
rm -- "$progress" "$metadata"
printf 'Completed: %d; results written to %s\n' "$completed" "$output" >&2
