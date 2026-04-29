#!/bin/bash
# netcheck v2.3 - Linux/Mac 一键启动脚本
cd "$(dirname "$0")"

echo "========================================"
echo "  netcheck v2.3 一键启动"
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
    echo "[错误] 未找到 Python，请先安装 Python 3.8+"
    if [ "$(uname)" = "Darwin" ]; then
        echo "  brew install python3"
    else
        echo "  Ubuntu/Debian: sudo apt install python3 python3-pip"
        echo "  CentOS/RHEL:   sudo yum install python3 python3-pip"
    fi
    exit 1
fi

# 检查 PyQt5
if ! "$PYTHON" -c "import PyQt5" 2>/dev/null; then
    echo "[提示] 正在安装 PyQt5，请稍候..."
    if [ "$(uname)" = "Darwin" ]; then
        "$PYTHON" -m pip install PyQt5 -i https://pypi.tuna.tsinghua.edu.cn/simple
    else
        if command -v sudo &>/dev/null; then
            sudo "$PYTHON" -m pip install PyQt5 -i https://pypi.tuna.tsinghua.edu.cn/simple
        else
            "$PYTHON" -m pip install PyQt5 -i https://pypi.tuna.tsinghua.edu.cn/simple
        fi
    fi
    if [ $? -ne 0 ]; then
        echo "[错误] PyQt5 安装失败，请手动运行: pip3 install PyQt5"
        exit 1
    fi
    echo "[完成] PyQt5 安装成功"
fi

echo "[启动] netcheck v2.3..."
"$PYTHON" "$(dirname "$0")/netcheck_v2.3.py"
