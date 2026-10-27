# PP 运行说明

完整流程分为两步：在开发机上合成初始化状态并进行 QEMU 测量，然后把生成的 JSON 交给板端测量脚本。

## 1. 开发机：`run_pp.sh`

需要 Python 及 `prof.py` 所需的 angr、claripy、Z3、ANTLR 等依赖，以及以下可执行程序：

- `riscv64-unknown-linux-gnu-gcc`
- `riscv64-unknown-linux-gnu-objdump`
- `qemu-riscv64`
- 项目中的 `tools/pp/pp`

在项目根目录运行：

```bash
bash run_pp.sh /path/to/non_fp.json -o /path/to/non_fp_pp.json
```

输入是 JSON 数组，每条记录必须包含非空 `asm` 字符串。输出保留原字段，并添加：

| 字段 | 内容 |
|---|---|
| `pp_init` | 初始化机器码文本，可以为空字符串 |
| `pp_code` | 被测基本块机器码文本 |
| `pp_result` | QEMU 测量的 `status`、`cycles`、`stdout`、`elapsed_s` |

`run_pp.sh` 是 Bash 启动入口，实际状态合成仍由 `src/rvmca/profile_json.py` 完成。

```bash
# 最多处理 10 条，每条最多 60 秒
bash run_pp.sh /path/to/non_fp.json -o /path/to/non_fp_pp.json --limit 10 --timeout 60

# 从输出文件继续，跳过已有成功记录
bash run_pp.sh /path/to/non_fp.json -o /path/to/non_fp_pp.json --resume

# 指定安装了依赖的 Python 解释器
PYTHON_BIN=/path/to/environment/bin/python bash run_pp.sh /path/to/non_fp.json -o /path/to/non_fp_pp.json

# 在终端显示诊断信息
bash run_pp.sh /path/to/non_fp.json -o /path/to/non_fp_pp.json --verbose
```

不传 `-o` 时会更新输入 JSON；首次覆盖已有目标文件时会保留 `.bak` 备份。每条处理完成后保存一次进度。QEMU 的 cycles 是模拟器测量结果。

## 2. 真实硬件：`tools/pp/run_pp_hardware.sh`

将生成的 JSON、`run_pp_hardware.sh` 和针对板端编译的 `pp` 放到板端。脚本默认执行与自身位于同一目录的 `pp`，也可用 `PP_BIN` 指定。

板端需要 Bash、jq 1.6 或更新版本、GNU `timeout`、`sha256sum`、`truncate`、支持 `sync -d` 的 `sync` 及常用 Linux 工具，无需 Python。

在项目根目录运行：

```bash
bash tools/pp/run_pp_hardware.sh /path/to/non_fp_pp.json
```

默认输出 `/path/to/non_fp_pp.board.json`，保留每条记录，并在末尾添加字符串字段：

```json
"board": "pp 的完整标准输出，包括采样记录和 cycles"
```

指定输出文件和结果字段名：

```bash
bash tools/pp/run_pp_hardware.sh /path/to/non_fp_pp.json /path/to/results.json starfive

# 等价的字段参数写法
bash tools/pp/run_pp_hardware.sh /path/to/non_fp_pp.json /path/to/results.json --key starfive
```

如果已经进入板端的 `pp` 目录：

```bash
bash run_pp_hardware.sh /path/to/non_fp_pp.json /path/to/results.json board
```

运行参数通过环境变量设置：

```bash
PP_BIN=/path/to/pp PP_TIMEOUT=5 BATCH_SIZE=100 REST_TIME=3 \
  bash tools/pp/run_pp_hardware.sh /path/to/non_fp_pp.json /path/to/results.json board
```

| 变量 | 默认值 | 含义 |
|---|---|---|
| `PP_BIN` | 脚本同目录的 `pp` | 板端可执行程序 |
| `PP_TIMEOUT` | `60` | 每条记录的测量超时秒数 |
| `BATCH_SIZE` | `100` | 每批记录数；`0` 禁用休息 |
| `REST_TIME` | `3` | 批间休息秒数 |

输入从 `pp_init`、`pp_code` 读取代码，也兼容旧字段 `init_binary`、`block_binary`。缺失代码、超时或程序非零退出时，结果字段分别写入 `SKIP:`、`TIMEOUT:`、`ERROR:` 信息。

脚本通过 `jq --stream` 逐条读取；每完成一条，就写入输出 JSON 并刷盘。输入与输出必须是不同文件。中断时会保留 `.progress.jsonl` 和 `.progress.meta.json`，执行相同命令即可续跑；全部完成后自动删除这两个进度文件。

输入内容、`pp` 二进制或字段名改变后，旧进度不能继续使用。确需从头测量时：

```bash
bash tools/pp/run_pp_hardware.sh /path/to/non_fp_pp.json /path/to/results.json board --force
```
