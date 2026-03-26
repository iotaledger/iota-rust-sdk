# 外部环境构建 - 具体执行命令

## 前提条件
1. 一台可访问互联网的机器 (Linux/macOS)
2. 至少200MB磁盘空间
3. 基本的命令行操作能力

## 步骤1: 准备环境

### Linux/macOS
```bash
# 1. 安装必要工具
sudo apt-get update && sudo apt-get install -y curl git tar  # Ubuntu/Debian
# 或
sudo yum install -y curl git tar  # CentOS/RHEL

# 2. 克隆项目 (如果有git)
git clone https://github.com/your-org/iota-defi-starter-kit
cd iota-defi-starter-kit

# 3. 如果没有git，手动下载
mkdir iota-defi-starter-kit && cd iota-defi-starter-kit
curl -L -o project.zip https://github.com/your-org/iota-defi-starter-kit/archive/main.zip
unzip project.zip && mv iota-defi-starter-kit-main/* . && rm -rf iota-defi-starter-kit-main
```

## 步骤2: 自动构建缓存

```bash
# 1. 给脚本执行权限
chmod +x scripts/external_build.sh

# 2. 运行构建脚本 (最简单选项)
./scripts/external_build.sh --cache-only

# 3. 或使用详细选项
./scripts/external_build.sh --output-dir ~/offline_build
```

## 步骤3: 检查生成文件

```bash
# 查看生成的目录
ls -la offline_build_*/

# 检查生成的文件
ls -lh offline_build_*/*.tar.gz offline_build_*/*.md5

# 查看构建报告
cat offline_build_*/BUILD_REPORT.md
```

## 步骤4: 准备传输

### 选项A: U盘传输
```bash
# 1. 找到U盘挂载点
lsblk  # 查看磁盘设备
sudo mount /dev/sdX1 /mnt  # 挂载U盘

# 2. 复制文件
cp -r offline_build_* /mnt/

# 3. 安全卸载
sync && sudo umount /mnt
```

### 选项B: 内网传输
```bash
# 1. 启动HTTP服务 (Python)
cd offline_build_* && python3 -m http.server 8000

# 2. 在受限环境用curl下载 (如果有限网络)
# curl -O http://<ip>:8000/sui-framework-cache.tar.gz
```

### 选项C: 云存储
```bash
# 1. 压缩整个目录
tar -czf offline_build.tar.gz offline_build_*/

# 2. 上传到百度网盘/阿里云OSS等
# (通过浏览器或客户端上传)
```

## 步骤5: 受限环境导入命令

### 导入脚本方式
```bash
# 1. 解压传输的文件 (如果是压缩包)
tar -xzf offline_build.tar.gz

# 2. 进入目录
cd offline_build_YYYYMMDD_HHMMSS

# 3. 运行导入脚本
chmod +x import_cache.sh
./import_cache.sh

# 4. 验证导入成功
ls -la ~/.sui/ | head -10
```

### 手动导入方式
```bash
# 1. 备份现有缓存
[ -d ~/.sui ] && mv ~/.sui ~/.sui.backup.$(date +%Y%m%d_%H%M%S)

# 2. 解压缓存
tar -xzf sui-framework-cache.tar.gz -C ~/

# 3. 验证
ls -la ~/.sui/sui-framework/ 2>/dev/null | head -5
```

## 故障排除

### 问题1: 脚本执行权限
```bash
chmod +x scripts/*.sh
```

### 问题2: 磁盘空间不足
```bash
# 检查空间
df -h .

# 清理临时文件
rm -rf /tmp/*.tar.gz
```

### 问题3: 网络下载慢
```bash
# 使用代理 (如果有)
export https_proxy=http://proxy.example.com:8080
export http_proxy=http://proxy.example.com:8080
```

### 问题4: Sui版本不匹配
```bash
# 检查版本
sui --version  # 应该显示 1.67.3

# 如果不匹配，下载正确版本
SUI_VERSION="mainnet-v1.67.3"
curl -L -o sui.tgz https://github.com/MystenLabs/sui/releases/download/$SUI_VERSION/sui-$SUI_VERSION-ubuntu-x86_64.tgz
tar -xzf sui.tgz
cp target/release/sui /usr/local/bin/
```

## 验证命令

### 在受限环境验证
```bash
# 1. 进入项目目录
cd iota-defi-starter-kit

# 2. 尝试构建
cd move_contracts/lending_pool
sui move build

# 3. 如果成功，继续验证
cd ../..
./scripts/build_no_docker.sh

# 4. 生成验证报告
echo "=== 构建验证成功 ===" > BUILD_SUCCESS.md
date >> BUILD_SUCCESS.md
sui --version >> BUILD_SUCCESS.md
find move_contracts -name "build" -type d | xargs ls -la >> BUILD_SUCCESS.md
```

## 快速检查清单

- [ ] 外部机器有网络访问
- [ ] 安装了curl/git/tar工具
- [ ] 成功运行 external_build.sh
- [ ] 生成了 sui-framework-cache.tar.gz
- [ ] 成功传输到受限环境
- [ ] 成功导入缓存
- [ ] Move合约构建成功

## 联系支持

如果遇到问题：
1. 保存错误信息
2. 检查日志文件
3. 联系项目维护团队
4. 提供错误详情和系统信息

---
*最后更新: $(date)*
*版本: v1.0 - 外部构建命令指南*