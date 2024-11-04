# RVMCA: RISC-V Machine Code Analyzer

RVMCA provides parsing, analysis and transformation
capabilities for RISC-V assembly code.

# Requirements

## Python Packages

- Python >= 3.11.5 

You could run `pip install -r requirements.txt` to configure necessary packages by one click. 
If pip fails in the process, use conda instead.

## Patched Packages

- vex (https://github.com/hahaxxz/vex)

```bash
# check the version of pyvex
pip list | grep pyvex
# download pyvex
# for example, get pyvex 9.2.125 in https://github.com/angr/pyvex/releases/tag/v9.2.125
cd pyvex-9.2.125
git clone https://github.com/hahaxxz/vex
cd vex
git checkout fix-riscv
make -f Makefile-gcc
cd ..
pip uninstall pyvex
pip install .
```

## Quick Start

```python
# for profiling
python src/rvmca/main.py -p input_file= tests/input/dv/test0.S

# for scheduling
python src/rvmca/main.py -rs input_file= tests/input/dv/test0.S -m 0
```

## Contributors

- Xuezheng (xuezhengxu@126.com)
- Deheng (dehengyang@qq.com)
