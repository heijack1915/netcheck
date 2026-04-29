# NetCheck

综合网络诊断工具，支持 DNS 查询、Ping 检测、TCP/UDP 端口探测、协议指纹识别、端口扫描、操作系统指纹识别以及 WAF 专项检测。

## 下载

前往 [Releases](https://github.com/heijack1915/netcheck/releases) 页面下载对应系统的压缩包：

| 系统 | 下载文件 | 说明 |
|------|----------|------|
| **Windows** | `netcheck_v2.3_windows.zip` | 解压后双击 `start_windows.bat` 启动 |
| **Mac / Linux** | `netcheck_v2.3_mac_linux.zip` | 解压后终端运行 `./start_mac_linux.sh` |
| **源码** | `Source code (zip)` | 需要自行安装 Python 3.8+ 和 PyQt5 |

> 前提条件：需要安装 [Python 3.8+](https://www.python.org/downloads/)（Windows 安装时请勾选 "Add Python to PATH"）。首次启动脚本会自动安装 PyQt5 依赖。

## 使用方法

### 一键启动（推荐）

**Windows：** 解压后双击 `start_windows.bat`

**Mac / Linux：**
```bash
chmod +x start_mac_linux.sh
./start_mac_linux.sh
```

### 手动启动

```bash
pip3 install PyQt5
python3 netcheck_v2.3.py          # GUI 模式
python3 netcheck_v2.3.py -d <IP>  # 命令行模式
```

### 打包为独立可执行文件（无需 Python）

```bash
chmod +x build.sh
./build.sh
```

打包后生成独立可执行文件，复制到任何机器双击即可运行。Windows 请在 Windows 上打包，Mac/Linux 同理。

## 功能

### 基础诊断

| 功能 | 说明 |
|------|------|
| DNS 查询 | 查询域名的 A、AAAA、MX、NS 等记录 |
| Ping 检测 | ICMP ping 测试，支持自定义包数量和大小 |
| TCP/UDP 探测 | 检测目标端口的 TCP 和 UDP 连通性 |

### 协议指纹识别

自动识别 HTTP、HTTPS、SSH、FTP、SMTP、MySQL、Redis、MongoDB、PostgreSQL、MQTT 等 16 种协议。

### 端口扫描

- 常用端口一键扫描（HTTP、SSH、MySQL、Redis 等 30+ 端口）
- 支持自定义端口范围
- 高并发扫描，速度较 v2.2 提升 50%

### OS 指纹识别

基于 TTL 值、SSH Banner、HTTP Server 头综合判断目标操作系统。

### WAF 专项检测（v2.3 新增）

检测 WAF 透明代理配置问题，验证端口是否返回预期协议：

| 默认端口 | 预期协议 | 说明 |
|----------|----------|------|
| 5677 | TCP | 期望直接转发 |
| 5678 | HTTP | WAF 正常代理 |
| 5679 | UDP | 期望直接转发 |

端口和协议均可在界面中自由编辑。

## 快捷操作

- **回车键**：输入框中按回车直接执行检测
- **导出 JSON**：检测结果可导出为 JSON 文件
- **WAF 端口配置**：支持添加/删除自定义检测端口

## 版本历史

- **v2.3** — WAF 专项检测、一键启动脚本、扫描速度优化
- **v2.2** — GUI 界面，多标签页操作
- **v2.1** — 基础 CLI 版本，端口扫描和 OS 指纹
