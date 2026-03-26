#!/bin/bash

set -e

echo "🚀 IOTA Move DeFi Starter Kit - 构建脚本"
echo "=" * 60

# 检查必需工具
check_tool() {
    if ! command -v $1 &> /dev/null; then
        echo "❌ 缺少必需工具: $1"
        echo "请安装 $1 后再运行此脚本"
        exit 1
    fi
}

echo "🔧 检查工具..."
check_tool "sui"
check_tool "cargo"
check_tool "git"
check_tool "docker"
check_tool "python3"

echo "✅ 所有必需工具已安装"

# 函数定义
build_move_contracts() {
    echo "\n📦 构建Move智能合约..."
    cd move_contracts
    
    # 检查每个合约目录
    for dir in lending_pool flash_loan oracle_integration liquidation; do
        if [ -d "$dir" ]; then
            echo "  🔨 构建 $dir..."
            cd "$dir"
            
            if [ -f "Move.toml" ]; then
                # 尝试构建
                if sui move build 2>/dev/null; then
                    echo "    ✅ $dir 构建成功"
                else
                    echo "    ⚠️  $dir 构建失败 (可能需要网络或依赖)"
                    echo "    建议: 使用Docker环境或检查网络连接"
                fi
            else
                echo "    ⚠️  $dir 缺少Move.toml"
            fi
            
            cd ..
        else
            echo "  ⚠️  目录 $dir 不存在"
        fi
    done
    
    cd ..
}

build_rust_examples() {
    echo "\n🦀 构建Rust示例..."
    cd rust_examples
    
    if [ -f "Cargo.toml" ]; then
        echo "  🔨 构建Rust项目..."
        if cargo build --release 2>/dev/null; then
            echo "    ✅ Rust项目构建成功"
            
            # 检查示例
            echo "  🔍 检查示例..."
            for example in deploy_and_init supply_and_borrow flash_loan_exec query_pool_state monitor_events; do
                if cargo run --example "$example" -- --help 2>&1 | grep -q "Usage:"; then
                    echo "    ✅ 示例 $example 可用"
                else
                    echo "    ⚠️  示例 $example 可能有问题"
                fi
            done
        else
            echo "    ⚠️  Rust项目构建失败"
            echo "    错误信息:"
            cargo build 2>&1 | tail -20
        fi
    else
        echo "  ⚠️  缺少Cargo.toml"
    fi
    
    cd ..
}

build_docker_image() {
    echo "\n🐳 构建Docker镜像..."
    
    if [ -f "Dockerfile" ]; then
        echo "  🔨 构建开发镜像..."
        if docker build -t iota-defi-dev:latest . 2>&1 | tail -5; then
            echo "    ✅ Docker镜像构建成功"
            echo "    运行: docker run -it --rm -v \$(pwd):/workspace iota-defi-dev:latest"
        else
            echo "    ⚠️  Docker镜像构建失败"
        fi
    else
        echo "  ⚠️  缺少Dockerfile"
    fi
}

check_multilingual_bindings() {
    echo "\n🌐 检查多语言绑定..."
    
    # Go
    if [ -d "go_examples" ]; then
        echo "  🔍 检查Go示例..."
        if [ -f "go_examples/main.go" ]; then
            echo "    ✅ Go示例文件存在"
            # 简单语法检查
            if command -v go &> /dev/null; then
                if go version > /dev/null 2>&1; then
                    echo "    ✅ Go工具链可用"
                fi
            fi
        else
            echo "    ⚠️  缺少Go示例文件"
        fi
    fi
    
    # Python
    if [ -d "python_examples" ]; then
        echo "  🔍 检查Python示例..."
        if [ -f "python_examples/deploy_and_init.py" ]; then
            echo "    ✅ Python示例文件存在"
            # 语法检查
            if python3 -m py_compile python_examples/deploy_and_init.py 2>/dev/null; then
                echo "    ✅ Python语法检查通过"
            fi
        else
            echo "    ⚠️  缺少Python示例文件"
        fi
    fi
    
    # Swift
    if [ -d "swift_examples" ]; then
        echo "  🔍 检查Swift示例..."
        if [ -f "swift_examples/DeFiExample.swift" ]; then
            echo "    ✅ Swift示例文件存在"
        else
            echo "    ⚠️  缺少Swift示例文件"
        fi
    fi
}

check_documentation() {
    echo "\n📚 检查文档..."
    
    required_docs=("README.md" "docs/architecture.md" "docs/deployment.md")
    
    for doc in "${required_docs[@]}"; do
        if [ -f "$doc" ]; then
            echo "    ✅ $doc 存在"
            
            # 检查文件大小
            size=$(wc -l < "$doc")
            if [ "$size" -lt 10 ]; then
                echo "      ⚠️  文件过小 ($size 行)，可能需要完善"
            fi
        else
            echo "    ⚠️  缺少 $doc"
        fi
    done
}

generate_report() {
    echo "\n📊 生成构建报告..."
    
    echo "构建时间: $(date)"
    echo "系统信息: $(uname -a)"
    echo "Sui版本: $(sui --version 2>/dev/null || echo '未知')"
    echo "Rust版本: $(rustc --version 2>/dev/null || echo '未知')"
    echo "Docker版本: $(docker --version 2>/dev/null || echo '未知')"
    
    echo "\n✅ 构建完成!"
    echo "\n💡 下一步建议:"
    echo "1. 使用Docker环境解决Move构建问题: docker-compose up -d sui-dev"
    echo "2. 运行测试: ./scripts/test.sh"
    echo "3. 查看文档: docs/deployment.md"
    echo "4. 探索示例: rust_examples/, go_examples/, python_examples/, swift_examples/"
}

# 主构建流程
echo "开始构建IOTA Move DeFi Starter Kit..."

# 1. 构建Move合约
build_move_contracts

# 2. 构建Rust示例
build_rust_examples

# 3. 构建Docker镜像
build_docker_image

# 4. 检查多语言绑定
check_multilingual_bindings

# 5. 检查文档
check_documentation

# 6. 生成报告
generate_report

echo "\n" * 60
echo "🎉 构建脚本执行完成!"
echo "\n如需帮助，请查看文档或提交Issue。"