# IOTA Move DeFi Starter Kit - 依赖需求清单

## 概述
由于当前腾讯云服务器网络限制，无法直接下载GitHub依赖。本清单详细说明构建所需的所有依赖及其获取方式。

## 核心依赖

### 1. Sui Framework (必需)
**用途**: Move智能合约编译的基础框架
**版本**: mainnet-v1.67.3 (必须与Sui CLI版本匹配)
**大小**: 约100-200MB (源码) / 50-100MB (编译缓存)

#### 获取方式
**方式A: 从GitHub下载源码**
```bash
# 在有网络的环境执行
git clone --depth 1 --branch mainnet-v1.67.3 https://github.com/MystenLabs/sui.git
cd sui
tar -czf sui-framework.tar.gz crates/sui-framework/
```

**方式B: 下载预编译缓存**
```bash
# 触发Sui CLI下载缓存
sui move build  # 在可访问网络的环境运行
tar -czf sui-framework-cache.tar.gz ~/.move/
```

**方式C: 使用镜像源** (如果可用)
```
https://hub.fastgit.org/MystenLabs/sui
https://ghproxy.com/https://github.com/MystenLabs/sui
```

### 2. Rust Crates (可选，用于Rust示例)
**用途**: Rust SDK示例编译
**主要依赖**: iota-sdk, serde, tokio等
**大小**: 约200-500MB

#### 获取方式
**方式A: 通过国内镜像源下载**
```bash
# 配置Cargo国内镜像
echo '[source.crates-io]
replace-with = "tuna"
[source.tuna]
registry = "https://mirrors.tuna.tsinghua.edu.cn/git/crates.io-index.git"' > ~/.cargo/config

# 下载依赖缓存
cargo fetch
tar -czf rust-cargo-cache.tar.gz ~/.cargo/registry/
```

**方式B: 跳过Rust示例编译**
```bash
# 在scripts/build_no_docker.sh中跳过Rust部分
```

### 3. Docker基础镜像 (可选)
**用途**: 容器化开发环境
**镜像**: `ubuntu:22.04` 或 `debian:bullseye-slim`
**大小**: 约50-100MB

#### 获取方式
**方式A: 使用腾讯云镜像加速器** (已在当前环境配置)
```bash
# 已配置 mirror.ccs.tencentyun.com
docker pull mirror.ccs.tencentyun.com/library/ubuntu:22.04
```

**方式B: 预下载镜像并传输**
```bash
# 在有Docker的环境拉取
docker pull ubuntu:22.04
docker save ubuntu:22.04 -o ubuntu-22.04.tar
```

## 文件传输清单

### 必需文件
| 文件 | 用途 | 大小 | 目标路径 |
|------|------|------|----------|
| `sui-framework.tar.gz` | Sui framework源码 | 100-200MB | `~/.move/git/https___github_com_MystenLabs_sui_git/` |
| 或 `sui-framework-cache.tar.gz` | 编译缓存 | 50-100MB | `~/.move/` |

### 可选文件
| 文件 | 用途 | 大小 | 目标路径 |
|------|------|------|----------|
| `rust-cargo-cache.tar.gz` | Rust依赖缓存 | 200-500MB | `~/.cargo/` |
| `ubuntu-22.04.tar` | Docker基础镜像 | 50-100MB | 任意位置，`docker load`导入 |
| `sui-cli.tar.gz` | Sui CLI二进制 | 195MB | `/usr/local/bin/` |

## 传输方式

### 方式1: U盘/移动硬盘 (推荐)
```bash
# 外部环境准备
tar -czf iota-deps-$(date +%Y%m%d).tar.gz \
  sui-framework.tar.gz \
  rust-cargo-cache.tar.gz

# 传输到腾讯云服务器后
tar -xzf iota-deps-YYYYMMDD.tar.gz
```

### 方式2: 腾讯云内网传输
```bash
# 如果有多台腾讯云服务器
scp -i key.pem deps.tar.gz user@10.1.x.x:/tmp/
```

### 方式3: 腾讯云对象存储(COS)
```bash
# 上传到COS
coscmd upload deps.tar.gz /

# 从腾讯云服务器下载
coscmd download /deps.tar.gz ./
```

## 依赖导入脚本

### 脚本位置
`scripts/import_dependencies.sh`

### 使用方式
```bash
# 1. 将依赖文件放入项目根目录的deps/文件夹
mkdir -p deps/
# 放入: sui-framework.tar.gz, rust-cargo-cache.tar.gz等

# 2. 运行导入脚本
chmod +x scripts/import_dependencies.sh
./scripts/import_dependencies.sh

# 3. 验证导入
./scripts/verify_dependencies.sh
```

## 项目配置修改

### Move.toml配置
支持本地和远程依赖的fallback配置：
```toml
[dependencies]
# 优先使用本地路径
Sui = { local = "../sui-framework", dev = false }

# 如果本地不存在，fallback到Git
# Sui = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework", rev = "mainnet-v1.67.3" }
```

### 环境变量配置
```bash
# 设置本地依赖路径
export MOVE_HOME=~/.move
export SUI_FRAMEWORK_PATH=~/.move/sui-framework
```

## 验证步骤

### 步骤1: 依赖完整性检查
```bash
./scripts/check_dependencies.sh
```

### 步骤2: 构建测试
```bash
cd move_contracts/lending_pool
sui move build
```

### 步骤3: 完整项目验证
```bash
./scripts/build_no_docker.sh
```

## 故障排除

### 问题1: 依赖路径不匹配
```bash
# 检查实际路径
find ~/.move -name "*.move" -type f | head -5

# 创建符号链接
ln -s /path/to/sui-framework ~/.move/sui-framework
```

### 问题2: 版本不兼容
```bash
# 检查版本
sui --version
# 应该显示: sui 1.67.3

# 如果不匹配，重新下载对应版本
```

### 问题3: 权限问题
```bash
# 确保有读写权限
chmod -R 755 ~/.move/
chmod -R 755 ~/.cargo/
```

## 备用方案

### 方案A: 简化验证
如果无法获取完整依赖，至少验证项目结构：
```bash
# 运行基础验证
./scripts/validate_structure.sh
```

### 方案B: 生成离线构建包
创建包含所有依赖的完整离线包：
```bash
# 在有网络的环境
./scripts/create_offline_bundle.sh
```

### 方案C: 使用预构建环境
如果其他团队已有构建环境，请求导出：
```bash
# 导出完整环境
tar -czf iota-build-env.tar.gz \
  ~/.move \
  ~/.cargo \
  /usr/local/bin/sui
```

## 联系支持

如遇到依赖获取问题：
1. 联系项目维护团队获取预构建依赖包
2. 使用腾讯云工单系统咨询网络配置
3. 在项目GitHub Issues中寻求帮助

## 成功标准

### 必须完成
- [ ] Sui framework就位
- [ ] Move.toml配置正确
- [ ] 至少一个合约构建成功

### 推荐完成
- [ ] Rust依赖就位
- [ ] 所有合约构建成功
- [ ] 单元测试通过

### 可选完成
- [ ] Docker环境就绪
- [ ] 多语言绑定验证
- [ ] 部署测试通过

---
*生成时间: $(date)*
*版本: v1.0 - 依赖需求清单*