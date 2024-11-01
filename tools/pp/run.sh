#!/bin/bash

# 指定包含可执行程序的目录
code_dir="/home/xuezheng/PycharmProjects/rvmca/tests/output/code/"
result_dir="/home/xuezheng/PycharmProjects/rvmca/tests/output/result/"

# 检查目录是否存在
if [ ! -d "$code_dir" ]; then
    echo "Directory does not exist: $code_dir"
    exit 1
fi

if [ ! -d "$result_dir" ]; then
    mkdir $result_dir
fi

# 读取目录下所有可执行文件并运行
for code in "$code_dir"/*; do
    echo "Run pp $code"
    filename=$(basename "$code")
    output_file="$result_dir/$filename.out"
    qemu-riscv64 ./pp $code > $output_file
done