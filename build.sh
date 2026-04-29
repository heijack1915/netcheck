#!/bin/bash
# netcheck v2.3 - 打包为独立可执行文件（无需目标机器装 Python）
cd "$(dirname "$0")"

echo "========================================"
echo "  netcheck v2.3 打包工具"
echo "========================================"

# 查找 Python
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PYTHON="$cmd"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "[错误] 未找到 Python"
    exit 1
fi

# 检查/安装 PyInstaller
if ! "$PYTHON" -c "import PyInstaller" 2>/dev/null; then
    echo "[提示] 正在安装 PyInstaller..."
    "$PYTHON" -m pip install pyinstaller -i https://pypi.tuna.tsinghua.edu.cn/simple
fi

# 打包
echo "[打包中] 正在生成可执行文件，首次打包可能需要几分钟..."
"$PYTHON" -m PyInstaller \
    --onefile \
    --windowed \
    --name "netcheck_v2.3" \
    --clean \
    --noconfirm \
    netcheck_v2.3.py

if [ $? -eq 0 ]; then
    OS=$(uname)
    if [ "$OS" = "Darwin" ]; then
        DIST="dist/netcheck_v2.3"
    else
        DIST="dist/netcheck_v2.3"
    fi

    echo ""
    echo "[完成] 打包成功！"
    echo "  输出文件: $(dirname "$0")/$DIST"
    echo ""
    echo "  将此文件复制到目标机器，双击即可运行，无需安装 Python。"
else
    echo "[错误] 打包失败"
    exit 1
fi
