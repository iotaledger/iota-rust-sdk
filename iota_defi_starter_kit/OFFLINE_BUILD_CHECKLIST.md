# IOTA Move DeFi Starter Kit - 离线构建检查清单

## 概述
由于当前环境网络限制严格，无法在线下载构建依赖。本检查清单提供在**可访问外部网络的环境**中准备构建环境，然后传输到当前环境的方法。

## 步骤1: 外部环境准备 (有网络访问)

### 1.1 下载必要资源
```bash
# 在有网络访问的机器上执行

# 1. 克隆项目
git clone https://github.com/your-org/iota-defi-starter-kit
cd iota-defi-starter-kit

# 2. 下载Sui framework依赖
mkdir -p offline_deps
cd offline_deps

# 下载Sui CLI (如果需要)
SUI_VERSION="mainnet-v1.67.3"
curl -L -o "sui-$SUI_VERSION.tgz" \
  "https://github.com/MystenLabs/sui/releases/download/$SUI_VERSION/sui-$SUI_VERSION-ubuntu-x86_64.tgz"

# 3. 下载Rust crates (如果需要)
# 如果目标环境没有Rust，下载Rust安装器
curl --proto '=https' --tlsv1.2 -sSf -o rustup-init.sh https://sh.rustup.rs
```

### 1.2 方法A: 构建完整Docker镜像
```bash
# 构建开发镜像
docker build -t iota-defi-dev -f Dockerfile .

# 导出镜像
docker save iota-defi-dev -o iota-defi-dev.tar

# 计算MD5校验和
md5sum iota-defi-dev.tar > iota-defi-dev.tar.md5
```

### 1.3 方法B: 仅准备Sui framework缓存
```bash
# 1. 安装Sui CLI
tar -xzf sui-$SUI_VERSION.tgz
cp target/release/sui /usr/local/bin/

# 2. 触发framework下载
cd ../move_contracts/lending_pool
sui move build  # 这会下载framework到~/.sui/

# 3. 打包framework缓存
cd ../..
tar -czf sui-framework-cache.tar.gz ~/.sui/
```

## 步骤2: 传输构建产物

### 传输选项
| 方式 | 适用场景 | 注意事项 |
|------|----------|----------|
| **U盘/移动硬盘** | 物理相邻环境 | 检查文件系统兼容性 |
| **内网传输** | 同一局域网 | 需要网络连通性 |
| **云存储** | 有受限外网访问 | 如百度网盘、阿里云OSS |
| **直接复制** | 同一机器多用户 | 需要权限 |

### 文件清单
- `iota-defi-dev.tar` (Docker镜像, ~1-2GB)
- `sui-framework-cache.tar.gz` (framework缓存, ~100-200MB)
- `sui-$SUI_VERSION.tgz` (Sui CLI二进制, ~50-100MB)
- 校验和文件 (.md5)

## 步骤3: 当前环境导入 (受限网络环境)

### 3.1 验证传输完整性
```bash
# 检查MD5校验和
md5sum -c iota-defi-dev.tar.md5
```

### 3.2 方法A: 导入Docker镜像
```bash
# 1. 导入镜像
docker load -i iota-defi-dev.tar

# 2. 验证导入
docker images | grep iota-defi-dev

# 3. 启动开发环境
docker compose up -d sui-dev

# 4. 进入容器并构建
docker compose exec sui-dev bash
cd /workspace/move_contracts/lending_pool
sui move build
```

### 3.3 方法B: 导入Sui framework缓存
```bash
# 1. 解压缓存
tar -xzf sui-framework-cache.tar.gz -C ~/

# 2. 验证Sui CLI已安装
which sui || {
  # 如果没有安装，从传输的包中安装
  tar -xzf sui-$SUI_VERSION.tgz
  cp target/release/sui /usr/local/bin/
  chmod +x /usr/local/bin/sui
}

# 3. 构建Move合约
cd iota-defi-starter-kit/move_contracts/lending_pool
sui move build
```

## 步骤4: 验证构建结果

### 4.1 检查构建输出
```bash
# 检查是否生成了构建目录
ls -la build/

# 验证字节码文件
find build -name "*.mv" -type f | head -5

# 检查依赖解析
cat build/Move.lock 2>/dev/null | head -20
```

### 4.2 运行测试
```bash
# 运行Move单元测试
sui move test

# 检查测试输出
tail -50 test_output.log 2>/dev/null
```

## 步骤5: 多模块验证

### 5.1 验证所有Move合约
```bash
cd move_contracts
for dir in lending_pool flash_loan oracle_integration liquidation; do
  echo "=== Building $dir ==="
  cd $dir
  sui move build && echo "✅ $dir built successfully" || echo "❌ $dir build failed"
  cd ..
done
```

### 5.2 Rust示例验证
```bash
cd rust_examples

# 检查Cargo.toml
cat Cargo.toml

# 尝试构建（可能需要网络，跳过如果离线）
cargo check --offline 2>/dev/null && echo "✅ Rust syntax OK" || echo "⚠️ Rust check skipped"
```

## 故障排除

### 常见问题1: Docker导入失败
```
Error: No such image: iota-defi-dev
```
**解决方案**:
```bash
# 重新导入
docker load -i iota-defi-dev.tar
docker tag <image_id> iota-defi-dev:latest
```

### 常见问题2: Sui framework路径错误
```
Error: Cannot find module: Sui
```
**解决方案**:
```bash
# 检查缓存路径
ls -la ~/.sui/

# 设置环境变量
export SUI_FRAMEWORK_PATH="$HOME/.sui/sui-framework"
```

### 常见问题3: 权限问题
```
Permission denied
```
**解决方案**:
```bash
# Docker需要sudo或用户组
sudo usermod -aG docker $USER
# 重新登录生效

# 或使用Podman
podman load -i iota-defi-dev.tar
```

## 备选方案

### 方案C: 最小化本地构建
如果无法传输大文件，仅验证项目结构：
```bash
# 1. 验证Move合约语法
cd move_contracts/lending_pool
sui move syntax-check 2>/dev/null

# 2. 验证项目结构
cd ../..
./scripts/build_no_docker.sh

# 3. 生成验证报告
cat validation_report.md
```

### 方案D: 使用预构建环境
如果其他团队已有构建环境：
1. 请求他们导出`~/.sui/`目录
2. 按照步骤3.3导入
3. 确保Sui版本匹配 (1.67.3)

## 成功标准

### 必须完成
1. ✅ 至少一个Move合约构建成功
2. ✅ 项目结构验证通过
3. ✅ 依赖配置正确

### 推荐完成
1. 🔄 所有4个Move合约构建成功
2. 🔄 Rust示例语法检查通过
3. 🔄 多语言绑定文件验证

### 扩展验证
1. 🔄 单元测试执行
2. 🔄 部署脚本测试
3. 🔄 性能基准测试

## 时间估算

| 步骤 | 外部环境 | 传输 | 当前环境 | 总计 |
|------|----------|------|----------|------|
| 准备资源 | 30-60分钟 | - | - | 30-60分钟 |
| 构建镜像 | 10-30分钟 | - | - | 40-90分钟 |
| 传输文件 | - | 5-60分钟 | - | 45-150分钟 |
| 导入验证 | - | - | 15-30分钟 | 60-180分钟 |

**总计**: 1-3小时 (取决于网络速度和文件大小)

## 联系支持

如遇到问题：
1. 检查本检查清单的故障排除部分
2. 查看项目文档: `docs/deployment.md`
3. 保存错误日志供分析
4. 联系项目维护团队

---
*最后更新: $(date)*
*版本: v1.0*