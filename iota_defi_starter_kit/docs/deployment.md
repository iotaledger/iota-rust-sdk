# IOTA Move DeFi Starter Kit - 部署指南

## 概述

本文档提供IOTA Move DeFi Starter Kit的完整部署指南，包括本地开发环境设置、测试网络部署和生产环境部署。

## 系统要求

### 硬件要求
- **CPU**: 4核或以上 (推荐8核)
- **内存**: 8GB或以上 (推荐16GB)
- **存储**: 50GB可用空间
- **网络**: 稳定的互联网连接

### 软件要求
- **操作系统**: Ubuntu 22.04+ / macOS 12+ / Windows 11 (WSL2)
- **Docker**: 20.10+ (容器化部署)
- **Rust**: 1.70+ (本地开发)
- **Sui CLI**: 1.67.3+ (区块链交互)

## 快速开始

### 使用Docker (推荐)

#### 步骤1: 克隆项目
```bash
git clone https://github.com/your-org/iota-defi-starter-kit.git
cd iota-defi-starter-kit
```

#### 步骤2: 启动开发环境
```bash
# 使用docker-compose启动开发环境
docker-compose up -d sui-dev

# 进入开发容器
docker-compose exec sui-dev bash

# 在容器内构建项目
cd /workspace
./scripts/build.sh
```

#### 步骤3: 运行测试
```bash
# 在容器内运行测试
cd /workspace
./scripts/test.sh
```

### 本地开发环境

#### 步骤1: 安装依赖
```bash
# 运行自动安装脚本
chmod +x scripts/setup.sh
./scripts/setup.sh
```

#### 步骤2: 验证安装
```bash
# 检查工具版本
sui --version
rustc --version
cargo --version
```

#### 步骤3: 构建项目
```bash
# 构建所有Move合约
cd move_contracts
./build_all.sh
```

#### 步骤4: 运行测试
```bash
# 运行所有单元测试
cd move_contracts
./test_all.sh
```

## 详细部署步骤

### 1. 开发环境配置

#### Docker环境
```bash
# 构建开发镜像
docker build -t iota-defi-dev:latest .

# 运行开发容器
docker run -it --rm \
  -v $(pwd):/workspace \
  -v sui-cache:/workspace/.move \
  iota-defi-dev:latest \
  bash
```

#### 本地环境
```bash
# 安装Rust工具链
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# 安装Sui CLI
SUI_VERSION="mainnet-v1.67.3"
curl -L -o "/tmp/sui-$SUI_VERSION.tgz" \
  "https://github.com/MystenLabs/sui/releases/download/$SUI_VERSION/sui-$SUI_VERSION-ubuntu-x86_64.tgz"
tar -xzf "/tmp/sui-$SUI_VERSION.tgz" -C /tmp
sudo cp "/tmp/target/release/sui" /usr/local/bin/
sudo chmod +x /usr/local/bin/sui
```

### 2. Move合约部署

#### 配置网络
```bash
# 配置Sui测试网络
sui client switch --env testnet

# 创建新钱包（如果不存在）
sui client new-address ed25519
```

#### 部署合约
```bash
# 进入合约目录
cd move_contracts/lending_pool

# 发布合约
sui client publish --gas-budget 100000000

# 保存发布结果
# 记录Package ID和Object ID
```

#### 初始化合约
```bash
# 使用Rust SDK初始化
cargo run --example deploy_and_init
```

### 3. SDK部署

#### Rust SDK
```bash
# 构建SDK库
cd rust_examples
cargo build --release

# 运行示例
cargo run --example deploy_and_init
cargo run --example supply_and_borrow
cargo run --example flash_loan_exec
cargo run --example query_pool_state
cargo run --example monitor_events
```

#### 多语言绑定
```bash
# Go绑定
cd go_examples
go build ./...
go test ./...

# Python绑定
cd python_examples
pip install -r requirements.txt
python deploy_and_init.py

# Swift绑定
cd swift_examples
swift build
swift test
```

### 4. 测试网络部署

#### 部署到Sui Testnet
```bash
# 切换到测试网络
sui client switch --env testnet

# 部署所有合约
./scripts/deploy_testnet.sh

# 验证部署
./scripts/verify_deployment.sh
```

#### 测试网络交互
```bash
# 运行集成测试
./scripts/integration_test.sh

# 监控测试网络状态
./scripts/monitor_testnet.sh
```

### 5. 生产环境部署

#### 前提条件
1. **安全审计**: 完成第三方安全审计
2. **性能测试**: 通过压力测试和负载测试
3. **监控系统**: 设置完整的监控和告警
4. **灾难恢复**: 制定备份和恢复计划

#### 部署步骤
```bash
# 1. 准备生产配置
cp config/production.toml config.toml

# 2. 构建生产版本
./scripts/build_production.sh

# 3. 部署到主网
./scripts/deploy_mainnet.sh

# 4. 验证部署
./scripts/verify_mainnet.sh

# 5. 启动监控
./scripts/start_monitoring.sh
```

## 配置管理

### 环境配置
```toml
# config.toml
[network]
env = "testnet"  # testnet, mainnet, devnet
rpc_url = "https://fullnode.testnet.sui.io:443"
websocket_url = "wss://fullnode.testnet.sui.io:443"

[contracts]
lending_pool_package_id = "0x..."
flash_loan_package_id = "0x..."
oracle_integration_package_id = "0x..."
liquidation_package_id = "0x..."

[oracles]
switchboard_enabled = true
pyth_enabled = true
price_feed_ids = ["0x...", "0x..."]

[monitoring]
enabled = true
prometheus_url = "http://localhost:9090"
alertmanager_url = "http://localhost:9093"
```

### 网络配置
```bash
# 网络配置文件
# networks.toml
[testnet]
chain_id = "sui-testnet"
rpc_url = "https://fullnode.testnet.sui.io:443"
faucet_url = "https://faucet.testnet.sui.io/gas"

[mainnet]
chain_id = "sui"
rpc_url = "https://fullnode.mainnet.sui.io:443"

[devnet]
chain_id = "sui-devnet"
rpc_url = "https://fullnode.devnet.sui.io:443"
faucet_url = "https://faucet.devnet.sui.io/gas"
```

## 监控和运维

### 健康检查
```bash
# 运行健康检查
./scripts/health_check.sh

# 检查合约状态
./scripts/check_contract_status.sh

# 检查网络连接
./scripts/check_network_connectivity.sh
```

### 日志管理
```bash
# 查看合约日志
sui client events --package <package-id>

# 查看节点日志
docker logs sui-node

# 查看应用日志
tail -f logs/application.log
```

### 性能监控
```bash
# 监控性能指标
./scripts/monitor_performance.sh

# 生成性能报告
./scripts/generate_performance_report.sh

# 分析交易延迟
./scripts/analyze_transaction_latency.sh
```

## 故障排除

### 常见问题

#### 1. 网络连接问题
```bash
# 检查网络连接
ping fullnode.testnet.sui.io

# 检查RPC端点
curl -s https://fullnode.testnet.sui.io:443/health

# 切换RPC提供商
export SUI_RPC_URL="https://alternative-rpc.sui.io"
```

#### 2. Gas不足问题
```bash
# 申请测试网Gas
curl -X POST https://faucet.testnet.sui.io/gas -d '{"recipient": "<your-address>"}'

# 增加Gas预算
sui client publish --gas-budget 200000000
```

#### 3. 依赖下载失败
```bash
# 使用Docker环境
docker-compose up -d sui-dev

# 使用本地缓存
cp -r ~/.sui/sui_repo/framework ./move_contracts/framework
```

#### 4. 合约部署失败
```bash
# 检查Move.toml配置
cat Move.toml

# 清理并重新构建
sui move clean
sui move build

# 查看详细错误信息
sui move build --verbose
```

### 调试技巧

#### 启用调试日志
```bash
export RUST_LOG=debug
export SUI_LOG=debug
```

#### 使用Move调试器
```bash
# 启用调试模式
sui move build --debug

# 运行调试测试
sui move test --debug
```

#### 分析交易
```bash
# 查看交易详情
sui client tx-block <digest>

# 分析交易效果
sui client tx-effects <digest>
```

## 安全最佳实践

### 私钥管理
```bash
# 使用环境变量
export SUI_PRIVATE_KEY="..."

# 使用密钥文件
sui keytool import-private-key --key-file private.key

# 使用硬件钱包
# 配置Ledger或Trezor支持
```

### 合约安全
```bash
# 运行安全扫描
./scripts/security_scan.sh

# 检查已知漏洞
./scripts/vulnerability_check.sh

# 运行形式验证
sui move prove
```

### 网络安全
```bash
# 启用TLS加密
export SUI_ENABLE_TLS=true

# 配置防火墙规则
./scripts/configure_firewall.sh

# 设置访问控制
./scripts/setup_access_control.sh
```

## 升级和维护

### 合约升级
```bash
# 1. 准备新版本
sui move build --upgrade

# 2. 测试升级
sui move test --upgrade

# 3. 执行升级
sui client upgrade --package <old-package-id> --upgrade-cap <upgrade-cap-id>

# 4. 验证升级
./scripts/verify_upgrade.sh
```

### 数据迁移
```bash
# 备份现有数据
./scripts/backup_data.sh

# 执行数据迁移
./scripts/migrate_data.sh

# 验证数据完整性
./scripts/verify_data_integrity.sh
```

## 性能优化

### Gas优化
```bash
# 分析Gas使用
sui client gas --address <your-address>

# 优化Gas消耗
./scripts/optimize_gas.sh

# 批量交易
./scripts/batch_transactions.sh
```

### 存储优化
```bash
# 分析存储使用
./scripts/analyze_storage.sh

# 优化数据结构
./scripts/optimize_data_structures.sh

# 清理旧数据
./scripts/cleanup_old_data.sh
```

## 支持资源

### 官方文档
- [Sui官方文档](https://docs.sui.io/)
- [Move语言文档](https://move-language.github.io/move/)
- [IOTA文档](https://wiki.iota.org/)

### 社区支持
- [Discord社区](https://discord.gg/sui)
- [GitHub Issues](https://github.com/your-org/iota-defi-starter-kit/issues)
- [开发者论坛](https://forum.sui.io/)

### 工具和资源
- [Sui Explorer](https://suiexplorer.com/)
- [Sui Wallet](https://chrome.google.com/webstore/detail/sui-wallet/efilnkgphhbcdpnbppbdpaaallheecmk)
- [Move Analyzer](https://marketplace.visualstudio.com/items?itemName=move.move-analyzer)

## 更新日志

### 版本 0.1.0 (2026-03-14)
- 初始版本发布
- 4个核心DeFi模块
- Rust SDK示例
- 基本文档和部署指南

### 版本计划
- 0.2.0: 多语言SDK绑定
- 0.3.0: 性能优化和监控
- 1.0.0: 生产就绪版本

---

**注意**: 本文档会随着项目发展而更新。请定期查看最新版本。