#!/bin/bash

set -e

echo "🚀 IOTA Move DeFi Starter Kit - 外部环境构建脚本"
echo "=" * 60
echo "使用说明: 在有网络访问的机器上运行此脚本"
echo "生成构建产物后，传输到受限网络环境使用"
echo "=" * 60

# 配置
PROJECT_NAME="iota-defi-starter-kit"
SUI_VERSION="mainnet-v1.67.3"
OUTPUT_DIR="./offline_build_$(date +%Y%m%d_%H%M%S)"
DOCKER_IMAGE="iota-defi-dev"
CACHE_ONLY=false
BUILD_DOCKER=true

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --cache-only)
            CACHE_ONLY=true
            BUILD_DOCKER=false
            shift
            ;;
        --docker-only)
            CACHE_ONLY=false
            BUILD_DOCKER=true
            shift
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --help)
            echo "使用方法: $0 [选项]"
            echo "选项:"
            echo "  --cache-only    仅生成Sui framework缓存"
            echo "  --docker-only   仅生成Docker镜像"
            echo "  --output-dir <目录>  指定输出目录"
            echo "  --help          显示此帮助信息"
            exit 0
            ;;
        *)
            echo "未知选项: $1"
            exit 1
            ;;
    esac
done

# 创建输出目录
mkdir -p "$OUTPUT_DIR"
echo "📁 输出目录: $OUTPUT_DIR"

# 检查必需工具
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "❌ 缺少必需工具: $1"
        return 1
    fi
    return 0
}

echo "🔧 检查工具..."
for tool in curl git tar; do
    check_tool "$tool" || exit 1
done

if $BUILD_DOCKER; then
    check_tool docker || {
        echo "⚠️  Docker未安装，跳过Docker镜像构建"
        BUILD_DOCKER=false
    }
fi

echo "✅ 所有必需工具已安装"

# 函数：下载Sui CLI
download_sui_cli() {
    echo "📥 下载Sui CLI ($SUI_VERSION)..."
    local sui_tar="sui-$SUI_VERSION-ubuntu-x86_64.tgz"
    local download_url="https://github.com/MystenLabs/sui/releases/download/$SUI_VERSION/$sui_tar"
    
    if curl -L -o "$OUTPUT_DIR/$sui_tar" "$download_url"; then
        echo "  ✅ Sui CLI下载成功"
        
        # 提取验证
        echo "  🔍 验证下载文件..."
        tar -tzf "$OUTPUT_DIR/$sui_tar" | grep -q "target/release/sui" && echo "    ✅ 文件结构正确"
        
        # 创建校验和
        md5sum "$OUTPUT_DIR/$sui_tar" > "$OUTPUT_DIR/$sui_tar.md5"
        echo "    📝 MD5校验和已生成"
    else
        echo "  ❌ Sui CLI下载失败"
        return 1
    fi
}

# 函数：生成Sui framework缓存
generate_framework_cache() {
    echo "🔄 生成Sui framework缓存..."
    
    # 临时目录
    local temp_dir="/tmp/sui_cache_$(date +%s)"
    mkdir -p "$temp_dir"
    
    # 安装Sui CLI
    echo "  📦 安装Sui CLI..."
    local sui_tar="sui-$SUI_VERSION-ubuntu-x86_64.tgz"
    if [ ! -f "$OUTPUT_DIR/$sui_tar" ]; then
        download_sui_cli || return 1
    fi
    
    tar -xzf "$OUTPUT_DIR/$sui_tar" -C "$temp_dir"
    local sui_bin="$temp_dir/target/release/sui"
    
    if [ ! -f "$sui_bin" ]; then
        echo "  ❌ 未找到sui二进制文件"
        return 1
    fi
    
    chmod +x "$sui_bin"
    
    # 设置环境变量
    export SUI_BIN="$sui_bin"
    
    # 创建测试项目触发framework下载
    echo "  ⚡ 触发framework下载..."
    local test_dir="$temp_dir/test_project"
    mkdir -p "$test_dir/sources"
    
    cat > "$test_dir/Move.toml" << EOF
[package]
name = "test"
version = "0.1.0"

[addresses]
test = "0x0"

[dev-addresses]
test = "0x0"

[dependencies]
Sui = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework", rev = "$SUI_VERSION" }
EOF
    
    cat > "$test_dir/sources/test.move" << EOF
module test::test {
    struct Test has drop {}
}
EOF
    
    # 尝试构建（这会下载framework）
    cd "$test_dir"
    if timeout 300 "$sui_bin" move build 2>&1 | tail -5; then
        echo "  ✅ framework下载成功"
    else
        echo "  ⚠️  framework下载可能未完成，继续缓存现有文件"
    fi
    
    # 查找framework缓存
    local home_sui="$HOME/.sui"
    if [ -d "$home_sui" ]; then
        echo "  📁 找到Sui缓存目录: $home_sui"
        
        # 打包缓存
        echo "  📦 打包framework缓存..."
        tar -czf "$OUTPUT_DIR/sui-framework-cache.tar.gz" -C "$HOME" .sui/
        
        # 生成文件清单
        find "$home_sui" -type f | head -20 > "$OUTPUT_DIR/cache_files.txt"
        
        echo "  ✅ framework缓存已生成"
        echo "    文件: $OUTPUT_DIR/sui-framework-cache.tar.gz"
        echo "    大小: $(du -h "$OUTPUT_DIR/sui-framework-cache.tar.gz" | cut -f1)"
    else
        echo "  ❌ 未找到Sui缓存目录"
        return 1
    fi
    
    # 清理
    cd /
    rm -rf "$temp_dir"
}

# 函数：构建Docker镜像
build_docker_image() {
    echo "🐳 构建Docker镜像..."
    
    # 检查当前目录
    if [ ! -f "Dockerfile" ]; then
        echo "  ❌ 当前目录没有Dockerfile"
        return 1
    fi
    
    # 构建镜像
    if docker build -t "$DOCKER_IMAGE:latest" .; then
        echo "  ✅ Docker镜像构建成功"
        
        # 保存镜像
        echo "  💾 导出Docker镜像..."
        docker save "$DOCKER_IMAGE:latest" -o "$OUTPUT_DIR/$DOCKER_IMAGE.tar"
        
        # 生成校验和
        md5sum "$OUTPUT_DIR/$DOCKER_IMAGE.tar" > "$OUTPUT_DIR/$DOCKER_IMAGE.tar.md5"
        
        echo "  📊 镜像信息:"
        echo "    文件: $OUTPUT_DIR/$DOCKER_IMAGE.tar"
        echo "    大小: $(du -h "$OUTPUT_DIR/$DOCKER_IMAGE.tar" | cut -f1)"
        echo "    标签: $DOCKER_IMAGE:latest"
        
        # 显示镜像层信息
        docker history "$DOCKER_IMAGE:latest" --no-trunc | head -10 > "$OUTPUT_DIR/docker_layers.txt"
    else
        echo "  ❌ Docker镜像构建失败"
        return 1
    fi
}

# 函数：生成导入脚本
generate_import_scripts() {
    echo "📜 生成导入脚本..."
    
    # 受限环境导入脚本
    cat > "$OUTPUT_DIR/import_cache.sh" << 'EOF'
#!/bin/bash
# Sui framework缓存导入脚本
# 在受限网络环境中运行

set -e

echo "🔧 导入Sui framework缓存..."
echo "=" * 40

# 检查文件
if [ ! -f "sui-framework-cache.tar.gz" ]; then
    echo "❌ 未找到缓存文件: sui-framework-cache.tar.gz"
    exit 1
fi

# 备份现有缓存
if [ -d "$HOME/.sui" ]; then
    echo "📁 备份现有缓存..."
    mv "$HOME/.sui" "$HOME/.sui.backup.$(date +%Y%m%d_%H%M%S)"
fi

# 导入缓存
echo "📦 解压缓存..."
tar -xzf sui-framework-cache.tar.gz -C "$HOME"

# 验证导入
if [ -d "$HOME/.sui" ]; then
    echo "✅ 缓存导入成功"
    echo "   目录: $HOME/.sui"
    echo "   文件数: $(find "$HOME/.sui" -type f | wc -l)"
else
    echo "❌ 缓存导入失败"
    exit 1
fi

# 检查Sui CLI
if command -v sui > /dev/null; then
    echo "🔍 Sui CLI已安装: $(sui --version)"
else
    echo "⚠️  Sui CLI未安装，需要手动安装"
    echo "   从离线包中复制: target/release/sui -> /usr/local/bin/sui"
fi

echo ""
echo "🚀 下一步:"
echo "   cd move_contracts/lending_pool"
echo "   sui move build"
EOF

    # Docker镜像导入脚本
    cat > "$OUTPUT_DIR/import_docker.sh" << 'EOF'
#!/bin/bash
# Docker镜像导入脚本
# 在受限网络环境中运行

set -e

echo "🐳 导入Docker镜像..."
echo "=" * 40

# 检查Docker
if ! command -v docker > /dev/null; then
    echo "❌ Docker未安装"
    exit 1
fi

# 检查文件
if [ ! -f "iota-defi-dev.tar" ]; then
    echo "❌ 未找到镜像文件: iota-defi-dev.tar"
    exit 1
fi

# 导入镜像
echo "📦 加载Docker镜像..."
docker load -i iota-defi-dev.tar

# 验证导入
if docker images | grep -q "iota-defi-dev"; then
    echo "✅ Docker镜像导入成功"
    
    # 显示镜像信息
    echo "📊 镜像信息:"
    docker images iota-defi-dev
    
    # 检查docker-compose
    if command -v docker-compose > /dev/null || docker compose version > /dev/null 2>&1; then
        echo "🔧 启动开发环境..."
        docker compose up -d sui-dev 2>/dev/null || docker-compose up -d sui-dev
        
        echo "✅ 开发环境已启动"
        echo "   容器: iota-defi-dev"
        echo "   进入容器: docker compose exec sui-dev bash"
    else
        echo "⚠️  docker-compose未安装"
        echo "   手动启动: docker run -it --rm -v \$(pwd):/workspace iota-defi-dev"
    fi
else
    echo "❌ Docker镜像导入失败"
    exit 1
fi
EOF

    # 设置执行权限
    chmod +x "$OUTPUT_DIR/import_cache.sh" "$OUTPUT_DIR/import_docker.sh"
    
    echo "✅ 导入脚本已生成"
    echo "   - import_cache.sh: 缓存导入脚本"
    echo "   - import_docker.sh: Docker镜像导入脚本"
}

# 主流程
main() {
    echo "开始外部环境构建准备..."
    
    # 下载Sui CLI（总是下载，作为备用）
    download_sui_cli
    
    # 生成framework缓存
    if $CACHE_ONLY || $BUILD_DOCKER; then
        generate_framework_cache || echo "⚠️  framework缓存生成失败，继续其他步骤"
    fi
    
    # 构建Docker镜像
    if $BUILD_DOCKER; then
        build_docker_image || echo "⚠️  Docker镜像构建失败"
    fi
    
    # 生成导入脚本
    generate_import_scripts
    
    # 生成构建报告
    cat > "$OUTPUT_DIR/BUILD_REPORT.md" << EOF
# 外部构建报告
生成时间: $(date)

## 生成的文件
$(ls -la "$OUTPUT_DIR" | tail -n +2 | awk '{print "- " $9 " (" $5 " bytes)"}')

## 构建选项
- 缓存生成: $CACHE_ONLY
- Docker构建: $BUILD_DOCKER
- Sui版本: $SUI_VERSION

## 使用说明
1. 将整个目录传输到受限网络环境
2. 根据需求运行导入脚本:
   - 仅使用缓存: ./import_cache.sh
   - 使用Docker: ./import_docker.sh
3. 验证构建: 进入项目目录运行构建命令

## 校验和
$(cat "$OUTPUT_DIR"/*.md5 2>/dev/null | sed 's/^/- /')

## 注意事项
1. 确保目标环境有足够的磁盘空间
2. Docker需要相应的权限
3. Sui CLI版本必须匹配 (1.67.3)
EOF
    
    echo ""
    echo "🎉 外部构建准备完成!"
    echo "📁 输出目录: $OUTPUT_DIR"
    echo "📦 总大小: $(du -sh "$OUTPUT_DIR" | cut -f1)"
    echo ""
    echo "🚀 下一步:"
    echo "  1. 传输整个目录到受限网络环境"
    echo "  2. 运行相应的导入脚本"
    echo "  3. 验证构建结果"
    echo ""
    echo "📄 详细说明: cat $OUTPUT_DIR/BUILD_REPORT.md"
}

# 执行主流程
main "$@"