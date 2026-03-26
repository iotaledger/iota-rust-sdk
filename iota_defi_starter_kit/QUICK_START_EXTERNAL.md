# 🔥 快速开始 - 外部构建方案

## 🎯 只需3步，今天拿下赏金！

### 第1步：在有网络的电脑上执行（30-60分钟）

```bash
# 1. 下载脚本包（如果无git，手动下载下面文件）
curl -O https://raw.githubusercontent.com/your-org/iota-defi-starter-kit/main/scripts/external_build.sh
curl -O https://raw.githubusercontent.com/your-org/iota-defi-starter-kit/main/scripts/configure_mirrors.sh

# 2. 运行构建
chmod +x external_build.sh
./external_build.sh
```

**或使用完整项目**：
```bash
git clone https://github.com/your-org/iota-defi-starter-kit
cd iota-defi-starter-kit
./scripts/external_build.sh
```

### 第2步：传输文件到服务器（5-30分钟）

构建完成后，将生成的文件夹传输到服务器：

**文件夹位置**：`offline_build_YYYYMMDD_HHMMSS/`

**传输方式**：
- ✅ **U盘**：最简单，直接复制
- ✅ **云存储**：压缩后上传下载  
- ✅ **内网**：如有其他腾讯云服务器

### 第3步：服务器导入验证（10-15分钟）

```bash
# 1. 进入传输的文件夹
cd offline_build_YYYYMMDD_HHMMSS/

# 2. 导入缓存
chmod +x import_cache.sh
./import_cache.sh

# 3. 验证成功
cd /root/.openclaw/workspace/iota_defi_starter_kit
cd move_contracts/lending_pool
sui move build  # 应该成功！
```

## 📁 必需文件清单

### 需要从服务器复制到外部电脑：
1. `scripts/external_build.sh` - 主构建脚本
2. `scripts/configure_mirrors.sh` - 镜像配置脚本

### 外部构建生成的传输文件：
1. `sui-framework-cache.tar.gz` - Sui framework缓存 (50-100MB)
2. `import_cache.sh` - 导入脚本
3. `BUILD_REPORT.md` - 构建报告

## ⏱️ 时间预估

| 任务 | 时间 | 状态 |
|------|------|------|
| 外部电脑准备 | 5-10分钟 | 🔄 |
| 运行构建脚本 | 30-60分钟 | 🔄 |
| 文件传输 | 5-30分钟 | 🔄 |
| 服务器导入 | 10-15分钟 | 🔄 |
| **总计** | **1-2小时** | **🎯** |

## ❓ 常见问题

### Q1：没有Linux/macOS电脑怎么办？
**A**：Windows安装WSL2，或使用手机热点+Termux

### Q2：网络很慢怎么办？
**A**：脚本支持断点续传，可分多次完成

### Q3：传输文件太大怎么办？
**A**：只传输`sui-framework-cache.tar.gz`和`import_cache.sh`

### Q4：遇到错误怎么办？
**A**：截图发我，立即提供解决方案

## 🚀 立即开始！

### 回复确认：
1. □ 已有外部电脑（带网络）
2. □ 选择传输方式：□ U盘 □ 云存储 □ 其他
3. □ 可以立即开始

**等待你的确认，立即指导执行！** 🐾💨

---
*生成时间: 2026-03-17 11:50 GMT+8*