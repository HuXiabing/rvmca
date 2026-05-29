#!/bin/bash

INPUT_SPEC="${1:-test.json}"
OUTPUT_FILE="${2:-output.json}"
BATCH_SIZE=100
TIMEOUT=5
REST_TIME=3

FILE_PATH="$INPUT_SPEC"
if [ ! -f "$FILE_PATH" ]; then
    echo "错误: 输入文件 $FILE_PATH 不存在"
    exit 1
fi

if [ ! -x "./pp" ]; then
    echo "警告: ./pp 不存在或不可执行"
    echo "将使用模拟结果进行处理"
    USE_MOCK=true
else
    USE_MOCK=false
fi

echo "开始处理 $INPUT_SPEC"
echo "输出文件: $OUTPUT_FILE"

echo "[" > "$OUTPUT_FILE"

count=0
total=0
first_item=true

while IFS= read -r block; do
    ((total++))
    ((count++))
    
    result=$(echo "$block" | jq -r '.result')
    
    if [ "$result" = "null" ] || [ -z "$result" ]; then
        echo "[$total] 跳过无效result"
        starfive_result="SKIP"
    else
        # 提取 <Init Code>
        init_code=$(echo "$result" | sed -n '/<Init Code>:\n/,/<Block>:\n/p' | sed '1d;$d')
        
        # 提取 <Block>
        block_code=$(echo "$result" | sed -n '/<Block>:\n/,/\[0\]:/p' | sed '1d;$d')
        
        # 保存到临时文件
        echo "$init_code" > temp.init
        echo "$block_code" > temp.code
        
        if [ "$USE_MOCK" = true ]; then
            # 模拟执行结果
            starfive_result="模拟结果: $(cat temp.init | wc -l) 行init + $(cat temp.code | wc -l) 行code"
        else
            # 执行 ./pp 命令
            result=$(timeout "$TIMEOUT" ./pp temp.init temp.code 2>&1)
            exit_code=$?
            
            if [ $exit_code -eq 124 ]; then
                echo "  -> 超时"
                starfive_result="TIMEOUT"
            elif [ $exit_code -ne 0 ]; then
                echo "  -> 错误 (退出码: $exit_code)"
                starfive_result="ERROR: $result"
            else
                starfive_result="$result"
            fi
        fi
    fi
    
    modified_block=$(echo "$block" | jq --arg starfive "$starfive_result" '. + {starfive: $starfive}')
    
    if [ "$first_item" = true ]; then
        first_item=false
        echo "  $modified_block" >> "$OUTPUT_FILE"
    else
        echo ", $modified_block" >> "$OUTPUT_FILE"
    fi
    
    if [ $count -ge $BATCH_SIZE ]; then
        echo "已处理 $total 个基本块，休息 ${REST_TIME} 秒..."
        pkill -9 -f "./pp" 2>/dev/null
        sleep "$REST_TIME"
        count=0
    fi
done < <(jq -c '.[]' "$FILE_PATH")
echo "]" >> "$OUTPUT_FILE"

# 清理临时文件
rm -f temp.init temp.code

echo "处理完成！总共处理了 $total 个基本块"
echo "结果已保存到 $OUTPUT_FILE"
