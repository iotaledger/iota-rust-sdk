#!/bin/bash

set -e

echo "🚀 设置 IOTA Move DeFi Starter Kit 开发环境"

# 检查系统
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "⚠️  警告：此脚本专为Linux系统设计，当前系统：$(uname -s)"
fi

# 检查必需的工具
echo "🔧 检查必需工具..."
for cmd in curl tar git cargo rustc; do
    if ! command -v $cmd &> /dev/null; then
        echo "❌ 缺少必需工具：$cmd"
        exit 1
    fi
done

echo "✅ 所有必需工具已安装"

# 安装Sui CLI
echo "📦 安装Sui CLI..."
SUI_VERSION="mainnet-v1.67.3"
SUI_TAR="sui-$SUI_VERSION-ubuntu-x86_64.tgz"
SUI_URL="https://github.com/MystenLabs/sui/releases/download/$SUI_VERSION/sui-$SUI_VERSION-ubuntu-x86_64.tgz"

echo "📥 下载Sui CLI ($SUI_VERSION)..."
curl -L -o "/tmp/$SUI_TAR" "$SUI_URL"

echo "📂 解压Sui CLI..."
tar -xzf "/tmp/$SUI_TAR" -C /tmp

echo "📁 安装Sui CLI到/usr/local/bin..."
sudo cp "/tmp/target/release/sui" /usr/local/bin/sui
sudo chmod +x /usr/local/bin/sui

echo "✅ Sui CLI已安装：$(sui --version 2>/dev/null || echo '安装失败')"

# 设置Rust工具链
echo "🦀 设置Rust工具链..."
rustup update stable
rustup default stable
rustup component add rustfmt clippy

echo "✅ Rust工具链就绪：$(rustc --version)"

# 克隆IOTA Rust SDK（如果尚未存在）
IOTA_SDK_DIR="/root/.openclaw/workspace/iota_defi_starter"
if [ ! -d "$IOTA_SDK_DIR" ]; then
    echo "📦 克隆IOTA Rust SDK..."
    gh repo clone iotaledger/iota-rust-sdk "$IOTA_SDK_DIR"
else
    echo "✅ IOTA Rust SDK已存在：$IOTA_SDK_DIR"
fi

# 创建Move合约项目
echo "📁 创建Move合约项目结构..."
MOVE_DIR="/root/.openclaw/workspace/iota_defi_starter_kit/move_contracts"
cd "$MOVE_DIR"

# 初始化Move项目
if [ ! -f "Move.toml" ]; then
    sui move new lending_pool
    sui move new flash_loan
    sui move new oracle_integration
    sui move new liquidation
    
    echo "✅ Move项目已初始化"
else
    echo "✅ Move项目已存在"
fi

# 创建Rust示例项目
echo "📁 创建Rust示例项目..."
RUST_EXAMPLES_DIR="/root/.openclaw/workspace/iota_defi_starter_kit/rust_examples"
cd "$RUST_EXAMPLES_DIR"

if [ ! -f "Cargo.toml" ]; then
    cat > Cargo.toml << EOF
[package]
name = "iota_defi_examples"
version = "0.1.0"
edition = "2021"

[dependencies]
iota-sdk = { path = "../iota_defi_starter/iota-sdk" }
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
anyhow = "1.0"

[[example]]
name = "deploy_and_init"

[[example]]
name = "supply_and_borrow"

[[example]]
name = "flash_loan_exec"

[[example]]
name = "query_pool_state"

[[example]]
name = "monitor_events"
EOF

    mkdir -p examples src
    
    echo "✅ Rust示例项目已创建"
else
    echo "✅ Rust示例项目已存在"
fi

# 安装Python绑定依赖（可选）
echo "🐍 安装Python绑定依赖..."
if command -v pip3 &> /dev/null; then
    pip3 install --upgrade pip
    echo "✅ Python工具就绪"
else
    echo "⚠️  Python未安装，跳过Python绑定"
fi

echo ""
echo "🎉 环境设置完成！"
echo ""
echo "下一步："
echo "1. 进入Move合约目录：cd /root/.openclaw/workspace/iota_defi_starter_kit/move_contracts"
echo "2. 构建合约：sui move build"
echo "3. 运行测试：sui move test"
echo "4. 进入Rust示例目录：cd /root/.openclaw/workspace/iota_defi_starter_kit/rust_examples"
echo "5. 运行示例：cargo run --example deploy_and_init"
echo ""
echo "💡 提示：阅读 docs/architecture.md 了解项目架构"