#!/bin/bash

# 创建日志目录
mkdir -p logs

# 配置文件路径
CONFIG_FILE="./rules/pickle_analysis_config.json"

# 遍历examples目录下的所有Python文件
for py_file in examples/*.py; do
  # 获取文件名（不含路径和扩展名）
  filename=$(basename "$py_file" .py)
  
  
  echo "===== 分析文件: $py_file ====="
  
  # 构建输出文件路径
  output_file="examples/${filename}_analysis.json"
  log_file="logs/${filename}_analysis.log"
  
  # 运行lanalyzer命令
  lanalyzer --target "$py_file" \
            --config "$CONFIG_FILE" \
            --pretty \
            --output "$output_file" \
            --log-file "$log_file" \
            --debug
  
  echo "分析结果已保存到: $output_file"
  echo "日志文件已保存到: $log_file"
  echo ""
done

echo "所有文件分析完成！" 