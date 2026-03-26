# IOTA Move DeFi Starter Kit

GitHub Bounty: [iotaledger/iota-rust-sdk/issues/1027](https://github.com/iotaledger/iota-rust-sdk/issues/1027)

## 概述
为IOTA生态系统开发完整的DeFi启动工具包，包括：
1. **Move智能合约**：借贷池、闪电贷、预言机集成、清算模块
2. **Rust SDK示例**：多语言绑定的完整使用示例
3. **文档**：架构指南、部署说明、代码注释

## 技术栈
- **Move智能合约**（基于Sui Move，适配IOTA）
- **Rust SDK**（IOTA Rust SDK集成）
- **DeFi概念**：借贷池、闪电贷、预言机、清算

## 项目结构
```
iota_defi_starter_kit/
├── move_contracts/          # Move智能合约
│   ├── lending_pool/        # 借贷池模块
│   ├── flash_loan/          # 闪电贷模块  
│   ├── oracle_integration/  # 预言机集成
│   └── liquidation/         # 清算模块
├── rust_examples/           # Rust SDK示例
│   ├── deploy_and_init/     # 部署和初始化
│   ├── supply_and_borrow/   # 存入和借贷
│   ├── flash_loan_exec/     # 闪电贷执行
│   ├── query_pool_state/    # 查询池状态
│   └── monitor_events/      # 事件监控
├── docs/                    # 文档
│   ├── architecture.md      # 架构概述
│   ├── deployment.md        # 部署指南
│   └── mechanics.md         # DeFi机制解释
└── scripts/                 # 构建和测试脚本
```

## 验收标准（来自Issue）
### Move智能合约
- [ ] 借贷池模块：supply/borrow/repay/withdraw + 利率模型
- [ ] 闪电贷模块：单交易借贷+使用+还款 + 手续费
- [ ] 预言机消费模块：集成Switchboard/Pyth预言机喂价
- [ ] 清算模块：健康因子计算和抵押不足仓位清算
- [ ] 所有模块的单元测试（`sui move test`）

### Rust SDK示例
- [ ] 示例：使用`move_call`部署和初始化借贷池
- [ ] 示例：存入抵押品和借出资产
- [ ] 示例：执行闪电贷（单PTB内借+用+还）
- [ ] 示例：通过`move_view_call`查询池状态、用户仓位、利率
- [ ] 示例：通过`EventFilter`监控清算事件
- [ ] 所有绑定的示例（Go, Kotlin, Python, Swift, C#）

### 文档
- [ ] 包含架构概述和模块交互图的README
- [ ] localnet和testnet的部署指南
- [ ] 解释DeFi机制（利率模型、健康因子、闪电贷不变量）的代码注释

## 3天冲刺计划
### 第1天（2026-03-13）：环境搭建与基础建设
- [ ] 安装开发环境（Sui CLI, Rust工具链）
- [ ] 研究IOTA Move架构和SDK
- [ ] 创建项目结构和初始配置
- [ ] 学习现有DeFi合约模式

### 第2天（2026-03-14）：Move智能合约开发
- [ ] 开发借贷池模块（4小时）
- [ ] 开发闪电贷模块（2小时）
- [ ] 开发预言机集成模块（2小时）
- [ ] 开发清算模块（2小时）
- [ ] 编写单元测试（2小时）

### 第3天（2026-03-15）：Rust SDK示例与文档
- [ ] 开发Rust SDK示例（4小时）
- [ ] 创建多语言绑定示例（3小时）
- [ ] 编写完整文档（3小时）
- [ ] 最终测试和提交准备

## 开发环境
- **Sui CLI**: mainnet-v1.67.3
- **Rust**: 最新稳定版
- **IOTA Rust SDK**: 最新develop分支
- **操作系统**: Linux x86_64

## 开始使用
```bash
# 1. 安装依赖
./scripts/setup.sh

# 2. 构建Move合约
cd move_contracts && sui move build

# 3. 运行测试
sui move test

# 4. 运行Rust示例
cd rust_examples && cargo run --example deploy_and_init
```

## 贡献指南
1. Fork IOTA Rust SDK仓库
2. 创建新分支：`feat/defi-starter-kit`
3. 实现上述验收标准
4. 提交Pull Request到原仓库

## 许可证
Apache 2.0（与IOTA Rust SDK相同）