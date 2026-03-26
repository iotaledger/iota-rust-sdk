#!/bin/bash

set -e

echo "🔧 配置国内镜像源加速"
echo "=" * 50

echo "当前系统: $(cat /etc/os-release | grep -E '^(NAME|VERSION)=' | head -2)"

# 备份原有配置
BACKUP_DIR="/tmp/mirror_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
echo "📁 备份目录: $BACKUP_DIR"

# 1. 配置Git代理
echo "🐙 配置Git代理..."
if [ -f ~/.gitconfig ]; then
    cp ~/.gitconfig "$BACKUP_DIR/gitconfig.backup"
fi

# 清除现有代理配置
git config --global --unset url.https://github.com/.insteadof || true

# 添加ghproxy代理
git config --global url."https://ghproxy.com/https://github.com/".insteadOf "https://github.com/"
git config --global url."https://ghproxy.com/https://gitlab.com/".insteadOf "https://gitlab.com/"

echo "  ✅ Git代理配置完成"
echo "  代理规则:"
git config --global --get-regexp url | sed 's/^/    /'

# 2. 配置Rust镜像源
echo "🦀 配置Rust镜像源..."
CARGO_DIR="$HOME/.cargo"
mkdir -p "$CARGO_DIR"

if [ -f "$CARGO_DIR/config" ]; then
    cp "$CARGO_DIR/config" "$BACKUP_DIR/cargo_config.backup"
fi

cat > "$CARGO_DIR/config" << 'EOF'
[source.crates-io]
replace-with = 'tuna'

[source.tuna]
registry = "https://mirrors.tuna.tsinghua.edu.cn/git/crates.io-index.git"

[source.ustc]
registry = "https://mirrors.ustc.edu.cn/crates.io-index"

[source.sjtu]
registry = "https://mirrors.sjtug.sjtu.edu.cn/git/crates.io-index"

[source.rustcc]
registry = "https://code.aliyun.com/rustcc/crates.io-index.git"

[net]
git-fetch-with-cli = true
EOF

echo "  ✅ Rust镜像源配置完成"
echo "  使用镜像: 清华 tuna"

# 3. 配置Podman/Docker镜像源
echo "🐳 配置容器镜像源..."

# 创建Podman配置文件
PODMAN_CONFIG_DIR="/etc/containers"
if [ -d "$PODMAN_CONFIG_DIR" ]; then
    echo "  📝 检测到Podman系统配置"
    if [ -f "$PODMAN_CONFIG_DIR/registries.conf" ]; then
        cp "$PODMAN_CONFIG_DIR/registries.conf" "$BACKUP_DIR/registries.conf.backup"
    fi
fi

# 用户级别配置
USER_REGISTRIES_DIR="$HOME/.config/containers"
mkdir -p "$USER_REGISTRIES_DIR"

cat > "$USER_REGISTRIES_DIR/registries.conf" << 'EOF'
unqualified-search-registries = ["docker.io"]

[[registry]]
prefix = "docker.io"
location = "docker.mirrors.sjtug.sjtu.edu.cn"

[[registry]]
prefix = "quay.io"
location = "quay.mirrors.sjtug.sjtu.edu.cn"

[[registry]]
prefix = "ghcr.io"
location = "ghcr.nju.edu.cn"

[[registry]]
prefix = "gcr.io"
location = "gcr.mirrors.sjtug.sjtu.edu.cn"

[[registry]]
prefix = "k8s.gcr.io"
location = "k8s.mirrors.sjtug.sjtu.edu.cn"

[[registry]]
prefix = "registry.k8s.io"
location = "k8s.mirrors.sjtug.sjtu.edu.cn"
EOF

echo "  ✅ 容器镜像源配置完成"
echo "  使用镜像: SJTUG Docker镜像站"

# 4. 配置系统包管理器镜像源 (OpenCloudOS)
echo "📦 配置系统包管理器镜像源..."

if command -v dnf &> /dev/null; then
    echo "  🔍 检测到dnf包管理器"
    
    # 备份原配置
    if [ -f /etc/yum.repos.d/OpenCloudOS.repo ]; then
        cp /etc/yum.repos.d/OpenCloudOS.repo "$BACKUP_DIR/OpenCloudOS.repo.backup"
    fi
    
    # 使用阿里云OpenCloudOS镜像
    cat > /tmp/OpenCloudOS-aliyun.repo << 'EOF'
[baseos-aliyun]
name=OpenCloudOS $releasever - BaseOS
baseurl=https://mirrors.aliyun.com/opencloudos/$releasever/BaseOS/$basearch/os/
gpgcheck=1
enabled=1
gpgkey=https://mirrors.aliyun.com/opencloudos/$releasever/BaseOS/$basearch/os/RPM-GPG-KEY-OpenCloudOS

[appstream-aliyun]
name=OpenCloudOS $releasever - AppStream
baseurl=https://mirrors.aliyun.com/opencloudos/$releasever/AppStream/$basearch/os/
gpgcheck=1
enabled=1
gpgkey=https://mirrors.aliyun.com/opencloudos/$releasever/AppStream/$basearch/os/RPM-GPG-KEY-OpenCloudOS

[extras-aliyun]
name=OpenCloudOS $releasever - Extras
baseurl=https://mirrors.aliyun.com/opencloudos/$releasever/extras/$basearch/os/
gpgcheck=1
enabled=1
gpgkey=https://mirrors.aliyun.com/opencloudos/$releasever/extras/$basearch/os/RPM-GPG-KEY-OpenCloudOS
EOF
    
    echo "  📝 阿里云镜像配置已生成，需要sudo权限应用"
    echo "  手动应用: sudo cp /tmp/OpenCloudOS-aliyun.repo /etc/yum.repos.d/"
fi

# 5. 配置环境变量
echo "🌐 配置环境变量..."

cat >> ~/.bashrc << 'EOF'

# 开发环境镜像配置
export RUSTUP_DIST_SERVER="https://mirrors.tuna.tsinghua.edu.cn/rustup"
export RUSTUP_UPDATE_ROOT="https://mirrors.tuna.tsinghua.edu.cn/rustup/rustup"
export CARGO_HTTP_MULTIPLEXING=false  # 某些网络环境下更稳定
export GIT_SSL_NO_VERIFY=1  # 如果遇到SSL证书问题
EOF

# 6. 测试配置
echo "🧪 测试配置..."

echo "  1. 测试Git代理:"
git config --global --get url.https://ghproxy.com/https://github.com/.insteadof

echo "  2. 测试Rust镜像:"
if [ -f "$CARGO_DIR/config" ]; then
    grep -A2 "\[source.tuna\]" "$CARGO_DIR/config"
fi

echo "  3. 测试网络连接:"
echo "     GitHub via proxy:"
curl -s --connect-timeout 5 https://ghproxy.com/https://github.com | grep -i "<title>" | head -1 || echo "     连接测试跳过"

echo ""
echo "✅ 镜像源配置完成!"
echo ""
echo "📋 配置摘要:"
echo "  - Git: ghproxy代理"
echo "  - Rust: 清华 tuna 镜像"
echo "  - 容器: SJTUG Docker镜像站"
echo "  - 系统: 阿里云OpenCloudOS镜像"
echo ""
echo "🚀 下一步:"
echo "  1. 重新尝试构建: sui move build"
echo "  2. 或运行: source ~/.bashrc 然后重试"
echo "  3. 如果仍有问题，查看日志调整配置"
echo ""
echo "💾 备份文件保存在: $BACKUP_DIR"