# RVMCA: RISC-V Machine Code Analyzer

RVMCA provides parsing, analysis and transformation
capabilities for RISC-V assembly code.

# Requirements

## Python Packages

- Python >= 3.11.5 

You could run `pip install -r requirements.txt` to configure necessary packages by one click. 
If pip fails in the process, use conda instead.


## Quick Start

1. Install required packages:

```bash
pip install -r requirement.txt
```

2. Run demo

```python
python src/rvmca/main.py -p input_file= tests/input/dv/test0.S
```

## Contributors

- Xuezheng (xuezhengxu@126.com)
- Deheng (dehengyang@qq.com)
