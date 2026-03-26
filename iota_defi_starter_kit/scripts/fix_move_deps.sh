#!/bin/bash

set -e

echo "🔧 修复Move.toml依赖配置"
echo "=" * 50

SUI_VERSION="mainnet-v1.67.3"
DEPENDENCY_LINE='Sui = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework", rev = "'$SUI_VERSION'" }'

cd move_contracts

for dir in lending_pool flash_loan oracle_integration liquidation; do
    if [ -d "$dir" ] && [ -f "$dir/Move.toml" ]; then
        echo "📝 处理 $dir/Move.toml..."
        
        # 检查是否已有[dependencies]部分
        if grep -q "\[dependencies\]" "$dir/Move.toml"; then
            echo "  ⚠️  已存在[dependencies]部分，跳过"
            continue
        fi
        
        # 备份原文件
        cp "$dir/Move.toml" "$dir/Move.toml.backup.$(date +%Y%m%d_%H%M%S)"
        
        # 在[dev-addresses]后添加[dependencies]
        awk '
        /\[dev-addresses\]/ {
            print $0
            print ""
            print "[dependencies]"
            print "'"$DEPENDENCY_LINE"'"
            next
        }
        { print $0 }
        ' "$dir/Move.toml" > "$dir/Move.toml.new"
        
        mv "$dir/Move.toml.new" "$dir/Move.toml"
        
        echo "  ✅ 依赖添加完成"
        echo "  添加内容:"
        echo "  [dependencies]"
        echo "  $DEPENDENCY_LINE"
        
        # 显示修改后的文件尾部
        echo "  文件尾部内容:"
        tail -10 "$dir/Move.toml"
        echo ""
    else
        echo "❌ $dir 目录或Move.toml不存在"
    fi
done

echo ""
echo "✅ 所有Move.toml依赖配置已更新"
echo ""
echo "💡 下一步:"
echo "1. 尝试构建: sui move build (可能需要网络下载)"
echo "2. 或使用Docker环境: docker-compose up -d sui-dev"
echo "3. 检查构建结果: ls -la build/"
echo ""
echo "⚠️  注意: 如果网络连接有问题，建议使用Docker环境"