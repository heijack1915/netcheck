#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netcheck v2.3 - 网络端口连通性排查工具（优化版）
v2.2 基础上优化：
1. 扫描速度大幅提升（减少延迟，增加并发）
2. 新增 WAF 专项检测（5677/5678/5679 端口协议验证）
"""

import argparse
import concurrent.futures
import json
import os
import platform
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict, field

# PyQt5 导入
try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QGridLayout, QLabel, QLineEdit, QPushButton, QTextEdit,
        QComboBox, QSpinBox, QDoubleSpinBox, QCheckBox, QGroupBox,
        QTableWidget, QTableWidgetItem, QTabWidget, QProgressBar,
        QMessageBox, QFileDialog, QSplitter, QFrame, QStatusBar,
        QToolBar, QAction, QMenuBar, QMenu, QButtonGroup, QRadioButton
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
    from PyQt5.QtGui import QFont, QTextCursor, QIcon, QColor, QPalette
    PYQT5_AVAILABLE = True
except ImportError:
    PYQT5_AVAILABLE = False
    print("警告: PyQt5 未安装，请运行: pip install PyQt5")


# ═══════════════════════════ 常量定义 ═══════════════════════════

# 协议指纹库
PROTOCOL_FINGERPRINTS = {
    "http": {"patterns": [b"HTTP/", b"HTTP-Version", b"<html", b"<!DOCTYPE"], "default_port": [80, 8080, 443, 8443, 5678]},
    "ssh": {"patterns": [b"SSH-"], "default_port": [22]},
    "ftp": {"patterns": [b"220-", b"220 ", b"FTP"], "default_port": [21]},
    "smtp": {"patterns": [b"220 ", b"SMTP", b"ESMTP"], "default_port": [25, 465, 587]},
    "mysql": {"patterns": [b"\x00\x00\x00\x0a", b"\x00\x00\x00\x03", b"MySQL"], "default_port": [3306]},
    "redis": {"patterns": [b"+OK", b"-ERR", b"redis"], "default_port": [6379]},
    "mongodb": {"patterns": [b"ismaster", b"ok\x00", b"mongodb"], "default_port": [27017]},
    "postgresql": {"patterns": [b"PGP", b"PostgreSQL"], "default_port": [5432]},
    "elasticsearch": {"patterns": [b"cluster_name", b"\"name\"", b"\"version\""], "default_port": [9200, 9300]},
    "memcached": {"patterns": [b"STAT", b"ERROR", b"STORED"], "default_port": [11211]},
    "kafka": {"patterns": [b"metadata", b"brokers"], "default_port": [9092]},
    "rabbitmq": {"patterns": [b"AMQP", b"rabbitmq"], "default_port": [5672, 15672]},
    "mqtt": {"patterns": [b"MQTT"], "default_port": [1883, 8883]},
    "dns": {"patterns": [b"\x00\x00\x81\x80"], "default_port": [53]},
    "vnc": {"patterns": [b"RFB "], "default_port": [5900, 5901]},
    "rdp": {"patterns": [b"\x00\x00\x00\x00\x08\x00\x00\x00"], "default_port": [3389]},
}

# 常用端口列表
COMMON_PORTS = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"), (53, "DNS"),
    (80, "HTTP"), (110, "POP3"), (135, "MSRPC"), (139, "NetBIOS"), (143, "IMAP"),
    (443, "HTTPS"), (445, "SMB"), (993, "IMAPS"), (995, "POP3S"),
    (1433, "MSSQL"), (1521, "Oracle"), (1723, "PPTP"), (3306, "MySQL"),
    (3389, "RDP"), (5432, "PostgreSQL"), (5672, "RabbitMQ"), (5900, "VNC"),
    (6379, "Redis"), (6443, "K8s API"), (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"),
    (8888, "HTTP-Alt2"), (9090, "Prometheus"), (9200, "Elasticsearch"), (9300, "ES-Transport"),
    (11211, "Memcached"), (27017, "MongoDB"), (5677, "WAF-TCP"), (5678, "WAF-HTTP"), (5679, "WAF-UDP"),
]

# WAF 专项检测端口
WAF_PORTS = [5677, 5678, 5679]

# WAF 预期协议
WAF_EXPECTED = {
    5677: "tcp",
    5678: "http",
    5679: "udp"
}


# ═══════════════════════════ 工具函数 ═══════════════════════════

def run_cmd(cmd: List[str], timeout: int = 15) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "命令超时"
    except FileNotFoundError:
        return -1, "", f"命令不存在: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def is_root() -> bool:
    if platform.system() == "Windows":
        return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


# ═══════════════════════════ 诊断结果容器 ═══════════════════════════

@dataclass
class DiagResult:
    target_host: str = ""
    target_ip: str = ""
    target_port: int = 0
    protocol: str = "tcp"
    success: bool = False
    checks: List[Dict] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    open_ports: List[Dict] = field(default_factory=list)
    os_guess: Dict = field(default_factory=dict)
    waf_result: Dict = field(default_factory=dict)
    raw_output: str = ""

    def add_check(self, name: str, status: str, detail: str = "", data: dict = None):
        self.checks.append({"name": name, "status": status, "detail": detail, "data": data or {}})

    def add_suggestion(self, text: str):
        if text not in self.suggestions:
            self.suggestions.append(text)


# ═══════════════════════════ 核心检测函数（优化版）═══════════════════════════

def check_dns(host: str) -> Tuple[bool, str, List[str]]:
    """DNS解析"""
    try:
        result = socket.getaddrinfo(host, None)
        ips = list(set([r[4][0] for r in result]))
        return True, "DNS解析成功", ips
    except socket.gaierror as e:
        return False, f"DNS解析失败: {e}", []


def check_ping(host: str, count: int = 2) -> Tuple[bool, str, Dict]:
    """ICMP Ping 检测（优化：减少ping次数加快速度）"""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    cmd = ["ping", param, str(count), host]
    code, stdout, stderr = run_cmd(cmd, timeout=count * 3 + 3)

    data = {"packets_sent": 0, "packets_received": 0, "packet_loss": "100%", "rtt": None}

    if code == 0:
        data["packets_sent"] = count
        for line in stdout.split('\n'):
            if 'received' in line.lower():
                try:
                    parts = line.split(',')
                    for p in parts:
                        p = p.strip()
                        if 'received' in p:
                            data["packets_received"] = int(p.split()[0])
                        elif 'loss' in p:
                            data["packet_loss"] = p.split()[0]
                except:
                    pass
            if ('rtt' in line.lower() or 'time' in line.lower()) and data["rtt"] is None:
                try:
                    for p in line.split():
                        if p.lower().startswith('time'):
                            data["rtt"] = float(p.split('=')[1])
                            break
                except:
                    pass
        return True, f"Ping成功 (丢包率:{data['packet_loss']})", data
    return False, "Ping失败或主机不可达", data


def check_tcp_port_fast(host: str, port: int, timeout: float = 1.0) -> Dict:
    """快速TCP端口检测（优化版）"""
    result = {
        "port": port, "status": "closed", "protocol": "unknown",
        "response_time": None, "banner": "", "http_status": None, "server": "", "is_waf_port": port in WAF_PORTS
    }
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.time()
        conn = sock.connect_ex((host, port))
        result["response_time"] = (time.time() - start) * 1000

        if conn == 0:
            result["status"] = "open"

            # 快速读取banner（减少等待时间）
            try:
                sock.setblocking(False)
                try:
                    data = sock.recv(512)
                    if data:
                        result["banner"] = data[:200].decode('utf-8', errors='ignore')
                        detect_protocol_in_data(result, data)
                except socket.timeout:
                    pass
                except BlockingIOError:
                    pass
            except:
                pass

            # 发送HTTP探测（仅对非WAF端口）
            if result["protocol"] != "http" and port not in [5677, 5679]:
                try:
                    sock.setblocking(True)
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    time.sleep(0.15)  # 减少等待时间
                    data = sock.recv(1024)
                    if data:
                        result["banner"] = data[:500].decode('utf-8', errors='ignore')
                        detect_protocol_in_data(result, data)
                except:
                    pass

        sock.close()

    except socket.timeout:
        result["status"] = "filtered"
    except socket.error:
        result["status"] = "error"
    except Exception:
        result["status"] = "error"
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass

    return result


def detect_protocol_in_data(result: Dict, data: bytes):
    """从接收数据中检测协议"""
    if b"HTTP/" in data[:20] or b"<html" in data[:20]:
        result["protocol"] = "http"
        try:
            text = data.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')
            if lines and lines[0].startswith('HTTP/'):
                parts = lines[0].split(' ', 2)
                if len(parts) >= 2:
                    result["http_status"] = int(parts[1])
            for line in lines[1:]:
                if line.lower().startswith('server:'):
                    result["server"] = line.split(':', 1)[1].strip()
                    break
        except:
            pass
    else:
        for proto_name, proto_info in PROTOCOL_FINGERPRINTS.items():
            for pattern in proto_info.get("patterns", []):
                if pattern in data:
                    result["protocol"] = proto_name
                    break
            if result["protocol"] != "unknown":
                break


def check_udp_port_fast(host: str, port: int, timeout: float = 1.0) -> Dict:
    """快速UDP端口检测"""
    result = {
        "port": port, "status": "closed", "protocol": "udp",
        "response_time": None, "banner": "", "is_waf_port": port in WAF_PORTS
    }
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        start = time.time()
        sock.sendto(b"\x00", (host, port))
        try:
            data, _ = sock.recvfrom(256)
            result["response_time"] = (time.time() - start) * 1000
            result["status"] = "open"
            result["banner"] = data[:100].hex()
            # UDP 上检测 HTTP 异常
            if b"HTTP/" in data[:20]:
                result["protocol"] = "http"
                try:
                    text = data.decode('utf-8', errors='ignore')
                    lines = text.split('\r\n')
                    if lines and lines[0].startswith('HTTP/'):
                        parts = lines[0].split(' ', 2)
                        if len(parts) >= 2:
                            result["http_status"] = int(parts[1])
                except:
                    pass
        except socket.timeout:
            result["status"] = "open_no_response"
        sock.close()
    except Exception:
        result["status"] = "error"
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass
    return result


def scan_ports_fast(host: str, ports: List[int], timeout: float = 0.8, workers: int = 100) -> List[Dict]:
    """快速并发端口扫描（优化版）"""
    results = []
    lock = threading.Lock()

    def scan_port(port):
        # 判断是否为WAF端口，使用对应协议检测
        if port == 5679:
            result = check_udp_port_fast(host, port, timeout)
        else:
            result = check_tcp_port_fast(host, port, timeout)
        if result["status"] == "open":
            with lock:
                results.append({
                    "port": port,
                    "service": get_service_name(port),
                    "response_time": result.get("response_time"),
                    "protocol": result.get("protocol", "unknown"),
                    "server": result.get("server", ""),
                    "http_status": result.get("http_status"),
                    "is_waf_port": result.get("is_waf_port", False)
                })
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(scan_port, p) for p in ports]
        concurrent.futures.wait(futures, timeout=timeout * len(ports) / workers + 10)

    return sorted(results, key=lambda x: x["port"])


def get_service_name(port: int) -> str:
    """获取端口服务名称"""
    for p, name in COMMON_PORTS:
        if p == port:
            return name
    return "Unknown"


def detect_os_fast(host: str, open_ports: List[Dict]) -> Dict:
    """快速系统指纹识别"""
    os_info = {"os": "Unknown", "confidence": 0, "evidence": []}

    # TTL分析（只发1个包加快速度）
    param = "-n" if platform.system().lower() == "windows" else "-c"
    code, stdout, stderr = run_cmd(["ping", param, "1", host], timeout=3)
    if code == 0:
        for line in stdout.split('\n'):
            if 'ttl' in line.lower():
                try:
                    for p in line.split():
                        if p.lower().startswith('ttl'):
                            ttl = int(p.split('=')[1])
                            if ttl <= 64:
                                os_info["evidence"].append({"来源": "TTL", "值": f"TTL={ttl}", "推断": "Linux/macOS"})
                                os_info["confidence"] += 20
                            elif ttl <= 128:
                                os_info["evidence"].append({"来源": "TTL", "值": f"TTL={ttl}", "推断": "Windows"})
                                os_info["confidence"] += 20
                            break
                except:
                    pass

    # SSH Banner（仅在22端口开放时）
    if any(p["port"] == 22 for p in open_ports):
        result = check_tcp_port_fast(host, 22, 1.0)
        if result["status"] == "open" and result["banner"]:
            banner = result["banner"]
            if "Ubuntu" in banner:
                os_info["evidence"].append({"来源": "SSH Banner", "值": banner[:50], "推断": "Ubuntu Linux"})
                os_info["confidence"] = 80
            elif "Debian" in banner:
                os_info["evidence"].append({"来源": "SSH Banner", "值": banner[:50], "推断": "Debian Linux"})
                os_info["confidence"] = 80
            elif "CentOS" in banner or "Red Hat" in banner:
                os_info["evidence"].append({"来源": "SSH Banner", "值": banner[:50], "推断": "RHEL/CentOS"})
                os_info["confidence"] = 80

    # HTTP Server头
    http_ports = [p for p in open_ports if p.get("protocol") == "http"]
    for p in http_ports[:1]:  # 只检查第一个HTTP端口
        if p.get("server"):
            server = p["server"]
            if "nginx" in server.lower():
                os_info["evidence"].append({"来源": "HTTP Server", "值": server, "推断": "Linux"})
                os_info["confidence"] = max(os_info["confidence"], 60)
            elif "microsoft" in server.lower() or "iis" in server.lower():
                os_info["evidence"].append({"来源": "HTTP Server", "值": server, "推断": "Windows"})
                os_info["confidence"] = max(os_info["confidence"], 70)

    if os_info["confidence"] >= 75:
        os_info["os"] = os_info["evidence"][0]["推断"] if os_info["evidence"] else "Unknown"
    elif os_info["confidence"] >= 40:
        os_info["os"] = f"可能 {os_info['evidence'][0]['推断']}" if os_info["evidence"] else "Unknown"

    return os_info


def check_waf_ports(host: str, ports: list = None, expected: dict = None, timeout: float = 1.0) -> Dict:
    """WAF 专项检测：端口协议验证
    Args:
        host: 目标主机
        ports: 端口列表，默认 [5677, 5678, 5679]
        expected: 预期协议字典，默认 {5677: "tcp", 5678: "http", 5679: "udp"}
        timeout: 超时时间
    """
    if ports is None:
        ports = [5677, 5678, 5679]
    if expected is None:
        expected = {5677: "tcp", 5678: "http", 5679: "udp"}
    result = {
        "enabled": True,
        "ports": {},
        "anomalies": [],
        "summary": ""
    }

    for port in ports:
        port_result = {
            "port": port,
            "expected_protocol": expected.get(port, "tcp"),
            "detected_protocol": "unknown",
            "status": "unknown",
            "http_status": None,
            "server": "",
            "is_anomaly": False,
            "description": ""
        }

        if port == 5679:
            # UDP 端口检测
            check_result = check_udp_port_fast(host, port, timeout)
            port_result["detected_protocol"] = check_result.get("protocol", "unknown")
            port_result["status"] = check_result["status"]
            port_result["http_status"] = check_result.get("http_status")
        else:
            # TCP 端口检测
            check_result = check_tcp_port_fast(host, port, timeout)
            port_result["detected_protocol"] = check_result.get("protocol", "unknown")
            port_result["status"] = check_result["status"]
            port_result["http_status"] = check_result.get("http_status")
            port_result["server"] = check_result.get("server", "")

        # 检测异常
        expected_proto = expected.get(port, "tcp")
        detected = port_result["detected_protocol"]

        # 预期 TCP/UDP 但返回 HTTP = 异常
        if expected_proto in ["tcp", "udp"] and detected == "http":
            port_result["is_anomaly"] = True
            port_result["description"] = f"预期{expected_proto.upper()}协议，但检测到HTTP响应"
            if port_result["http_status"]:
                port_result["description"] += f" (HTTP {port_result['http_status']})"
            result["anomalies"].append({
                "port": port,
                "expected": expected_proto,
                "detected": "http",
                "description": port_result["description"],
                "suggestion": "疑似WAF错误配置，将非HTTP端口代理为HTTP，请检查WAF站点设置"
            })

        # 预期 HTTP 但返回 TCP/UDP = 异常
        if expected_proto == "http" and detected in ["tcp", "udp", "unknown"] and port_result["status"] == "open":
            # 如果端口开放但协议不对
            if detected != "http":
                port_result["is_anomaly"] = True
                port_result["description"] = f"预期HTTP协议，但检测到{detected.upper()}协议"
                result["anomalies"].append({
                    "port": port,
                    "expected": "http",
                    "detected": detected,
                    "description": port_result["description"],
                    "suggestion": "WAF代理可能未生效，检查WAF配置"
                })

        result["ports"][port] = port_result

    # 生成摘要
    if result["anomalies"]:
        result["summary"] = f"检测到 {len(result['anomalies'])} 个配置异常"
    else:
        result["summary"] = "未检测到明显异常"

    return result


# ═══════════════════════════ PyQt5 图形界面 ═══════════════════════════

class ScanThread(QThread):
    """扫描线程（优化版）"""
    progress = pyqtSignal(str)
    progress_percent = pyqtSignal(int)
    result_ready = pyqtSignal(dict)
    finished = pyqtSignal()

    def __init__(self, host, port, options):
        super().__init__()
        self.host = host
        self.port = port
        self.options = options
        self._is_running = True

    def run(self):
        try:
            result = {
                "dns": {"success": False, "ips": [], "message": ""},
                "ping": {"success": False, "message": "", "data": {}},
                "port": {"success": False, "data": {}},
                "open_ports": [],
                "os_guess": {},
                "waf_result": {}
            }

            # DNS解析
            self.progress.emit("[1/6] 正在解析 DNS...")
            self.progress_percent.emit(10)
            ok, msg, ips = check_dns(self.host)
            result["dns"] = {"success": ok, "ips": ips, "message": msg}
            self.progress.emit(f"  → {msg}")

            if not ips:
                self.result_ready.emit(result)
                self.finished.emit()
                return

            target_ip = ips[0]

            # Ping检测
            self.progress.emit("[2/6] 正在 Ping 检测...")
            self.progress_percent.emit(20)
            ok, msg, data = check_ping(target_ip)
            result["ping"] = {"success": ok, "message": msg, "data": data}
            self.progress.emit(f"  → {msg}")

            # 端口检测
            self.progress.emit(f"[3/6] 检测端口 {self.port}...")
            self.progress_percent.emit(30)
            protocol = self.options.get("protocol", "tcp")
            timeout = self.options.get("timeout", 1.0)

            if protocol == "udp":
                data = check_udp_port_fast(target_ip, self.port, timeout)
            else:
                data = check_tcp_port_fast(target_ip, self.port, timeout)
            result["port"] = {"success": data["status"] == "open", "data": data}
            self.progress.emit(f"  → 状态: {data['status']}, 协议: {data['protocol']}")

            # WAF 专项检测
            self.progress.emit("[4/6] WAF 专项检测...")
            self.progress_percent.emit(50)
            waf_ports = self.options.get("waf_ports", [5677, 5678, 5679])
            waf_expected = self.options.get("waf_expected", {5677: "tcp", 5678: "http", 5679: "udp"})
            waf_result = check_waf_ports(target_ip, waf_ports, waf_expected, timeout)
            result["waf_result"] = waf_result

            if waf_result["anomalies"]:
                self.progress.emit(f"  ⚠ {waf_result['summary']}")
                for anomaly in waf_result["anomalies"]:
                    self.progress.emit(f"    端口 {anomaly['port']}: {anomaly['description']}")
            else:
                self.progress.emit(f"  → {waf_result['summary']}")

            # 端口扫描
            if self.options.get("scan", False):
                self.progress.emit("[5/6] 正在扫描常用端口...")
                self.progress_percent.emit(60)
                scan_timeout = self.options.get("scan_timeout", 0.8)
                workers = self.options.get("workers", 100)

                # 扫描常用端口
                all_ports = [p for p, _ in COMMON_PORTS]
                result["open_ports"] = scan_ports_fast(target_ip, all_ports, scan_timeout, workers)
                self.progress.emit(f"  → 发现 {len(result['open_ports'])} 个开放端口")

                # 系统指纹
                if self.options.get("os_detect", False) and result["open_ports"]:
                    self.progress.emit("[6/6] 系统指纹识别...")
                    self.progress_percent.emit(90)
                    result["os_guess"] = detect_os_fast(target_ip, result["open_ports"])
                    self.progress.emit(f"  → {result['os_guess'].get('os', 'Unknown')} (置信度: {result['os_guess'].get('confidence', 0)}%)")
                else:
                    self.progress_percent.emit(100)
            else:
                self.progress_percent.emit(100)

            self.result_ready.emit(result)

        except Exception as e:
            self.progress.emit(f"错误: {str(e)}")
        finally:
            self.finished.emit()


class NetcheckGUI(QMainWindow):
    """主窗口（v2.3 优化版）"""

    def __init__(self):
        super().__init__()
        self.scan_thread = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("netcheck v2.3 - 网络端口连通性排查工具")
        self.setGeometry(100, 100, 1200, 800)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # ===== 目标设置 =====
        settings_group = QGroupBox("目标设置")
        settings_layout = QGridLayout()

        settings_layout.addWidget(QLabel("目标地址:"), 0, 0)
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("IP 地址或域名")
        settings_layout.addWidget(self.host_input, 0, 1)

        settings_layout.addWidget(QLabel("端口:"), 0, 2)
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("80, 443, 8080")
        self.port_input.setText("80")
        settings_layout.addWidget(self.port_input, 0, 3)

        settings_layout.addWidget(QLabel("协议:"), 1, 0)
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["TCP", "UDP"])
        settings_layout.addWidget(self.protocol_combo, 1, 1)

        settings_layout.addWidget(QLabel("超时(秒):"), 1, 2)
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(0.3, 10)
        self.timeout_spin.setValue(1.0)
        self.timeout_spin.setSingleStep(0.1)
        settings_layout.addWidget(self.timeout_spin, 1, 3)

        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)

        # ===== 选项设置 =====
        options_group = QGroupBox("扫描选项")
        options_layout = QGridLayout()

        self.scan_check = QCheckBox("扫描常用端口")
        self.os_check = QCheckBox("系统指纹识别")
        self.waf_check = QCheckBox("WAF专项检测")
        self.waf_check.setChecked(True)  # 默认启用

        options_layout.addWidget(self.scan_check, 0, 0)
        options_layout.addWidget(self.os_check, 0, 1)
        options_layout.addWidget(self.waf_check, 0, 2)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        # ===== WAF 端口配置（可编辑）=====
        waf_config_group = QGroupBox("WAF 端口配置（可编辑）")
        waf_config_layout = QGridLayout()

        # 表头
        waf_config_layout.addWidget(QLabel("端口"), 0, 0)
        waf_config_layout.addWidget(QLabel("预期协议"), 0, 1)
        waf_config_layout.addWidget(QLabel("说明"), 0, 2)

        # 默认配置：5677-TCP, 5678-HTTP, 5679-UDP
        self.waf_port_rows = []
        default_ports = [
            (5677, "tcp", "TCP端口，期望直接转发"),
            (5678, "http", "HTTP端口，WAF正常代理"),
            (5679, "udp", "UDP端口，期望直接转发")
        ]

        for i, (port, protocol, desc) in enumerate(default_ports, 1):
            # 端口输入
            port_input = QSpinBox()
            port_input.setRange(1, 65535)
            port_input.setValue(port)
            port_input.setMinimumWidth(80)

            # 协议选择
            proto_combo = QComboBox()
            proto_combo.addItems(["tcp", "http", "udp"])
            proto_combo.setCurrentText(protocol)
            proto_combo.setMinimumWidth(100)

            # 说明
            desc_label = QLabel(desc)
            desc_label.setStyleSheet("color: #6b7280;")

            waf_config_layout.addWidget(port_input, i, 0)
            waf_config_layout.addWidget(proto_combo, i, 1)
            waf_config_layout.addWidget(desc_label, i, 2)

            self.waf_port_rows.append((port_input, proto_combo))

        # 添加/删除按钮
        btn_row = len(default_ports) + 1
        add_btn = QPushButton("➕ 添加端口")
        add_btn.clicked.connect(lambda: self.add_waf_port_row(waf_config_layout))
        del_btn = QPushButton("➖ 删除最后一行")
        del_btn.clicked.connect(lambda: self.remove_waf_port_row(waf_config_layout))
        waf_config_layout.addWidget(add_btn, btn_row, 0)
        waf_config_layout.addWidget(del_btn, btn_row, 1)

        waf_config_group.setLayout(waf_config_layout)
        layout.addWidget(waf_config_group)

        self.full_check = QCheckBox("完整诊断")
        self.tcp_trace_check = QCheckBox("TCP路径追踪")
        options_layout.addWidget(self.full_check, 1, 0)
        options_layout.addWidget(self.tcp_trace_check, 1, 1)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        # ===== 按钮 =====
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("🚀 开始扫描")
        self.start_btn.clicked.connect(self.start_scan)
        self.start_btn.setStyleSheet("QPushButton { background-color: #2563eb; color: white; padding: 10px 20px; border: none; border-radius: 6px; font-size: 14px; } QPushButton:hover { background-color: #1d4ed8; }")

        self.stop_btn = QPushButton("⏹ 停止")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("QPushButton { background-color: #ef4444; color: white; padding: 10px 20px; border: none; border-radius: 6px; font-size: 14px; }")

        self.export_btn = QPushButton("💾 导出JSON")
        self.export_btn.clicked.connect(self.export_json)
        self.export_btn.setStyleSheet("QPushButton { background-color: #22c55e; color: white; padding: 10px 20px; border: none; border-radius: 6px; font-size: 14px; }")

        self.clear_btn = QPushButton("🗑 清除")
        self.clear_btn.clicked.connect(self.clear_results)
        self.clear_btn.setStyleSheet("QPushButton { background-color: #6b7280; color: white; padding: 10px 20px; border: none; border-radius: 6px; font-size: 14px; }")

        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.export_btn)
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # ===== 进度条 =====
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%p% - %s")
        layout.addWidget(self.progress_bar)

        # ===== 结果标签页 =====
        self.tabs = QTabWidget()

        # 实时输出
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Consolas", 10))
        self.tabs.addTab(self.output_text, "📊 实时输出")

        # 端口扫描结果
        self.port_table = QTableWidget()
        self.port_table.setColumnCount(7)
        self.port_table.setHorizontalHeaderLabels(["端口", "服务", "协议", "RTT", "HTTP状态", "Server", "WAF"])
        self.port_table.setColumnWidth(0, 70)
        self.port_table.setColumnWidth(1, 100)
        self.port_table.setColumnWidth(2, 70)
        self.port_table.setColumnWidth(3, 80)
        self.port_table.setColumnWidth(4, 90)
        self.port_table.setColumnWidth(5, 180)
        self.port_table.setColumnWidth(6, 60)
        self.tabs.addTab(self.port_table, "🔌 端口扫描")

        # WAF 检测结果
        self.waf_text = QTextEdit()
        self.waf_text.setReadOnly(True)
        self.waf_text.setFont(QFont("Consolas", 10))
        self.tabs.addTab(self.waf_text, "🛡️ WAF检测")

        # 系统指纹
        self.os_text = QTextEdit()
        self.os_text.setReadOnly(True)
        self.os_text.setFont(QFont("Consolas", 10))
        self.tabs.addTab(self.os_text, "💻 系统指纹")

        # JSON结果
        self.json_text = QTextEdit()
        self.json_text.setReadOnly(True)
        self.json_text.setFont(QFont("Consolas", 10))
        self.tabs.addTab(self.json_text, "📄 JSON")

        layout.addWidget(self.tabs)

        # ===== 状态栏 =====
        self.statusBar().showMessage("就绪")

        self.current_result = {}

    def append_output(self, text, color=None):
        if color:
            self.output_text.append(f'<span style="color: {color}">{text}</span>')
        else:
            self.output_text.append(text)
        cursor = self.output_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.output_text.setTextCursor(cursor)

    def add_waf_port_row(self, layout):
        """添加一行 WAF 端口配置"""
        row = len(self.waf_port_rows) + 1
        # 端口输入
        port_input = QSpinBox()
        port_input.setRange(1, 65535)
        port_input.setValue(80)
        port_input.setMinimumWidth(80)
        # 协议选择
        proto_combo = QComboBox()
        proto_combo.addItems(["tcp", "http", "udp"])
        proto_combo.setMinimumWidth(100)
        # 说明
        desc_label = QLabel("自定义端口")
        desc_label.setStyleSheet("color: #6b7280;")
        layout.addWidget(port_input, row, 0)
        layout.addWidget(proto_combo, row, 1)
        layout.addWidget(desc_label, row, 2)
        self.waf_port_rows.append((port_input, proto_combo))

    def remove_waf_port_row(self, layout):
        """删除最后一行 WAF 端口配置（保留至少3行）"""
        if len(self.waf_port_rows) > 3:
            row_data = self.waf_port_rows.pop()
            for widget in row_data:
                widget.deleteLater()

    def get_waf_config(self):
        """获取用户配置的 WAF 端口和协议"""
        ports = []
        expected = {}
        for port_input, proto_combo in self.waf_port_rows:
            port = port_input.value()
            protocol = proto_combo.currentText()
            ports.append(port)
            expected[port] = protocol
        return ports, expected

    def start_scan(self):
        host = self.host_input.text().strip()
        port_text = self.port_input.text().strip()

        if not host:
            QMessageBox.warning(self, "输入错误", "请输入目标地址")
            return
        if not port_text:
            QMessageBox.warning(self, "输入错误", "请输入端口")
            return

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("%p% - 扫描中...")
        self.output_text.clear()
        self.current_result = {}

        self.append_output("=" * 60, "#1e3a5f")
        self.append_output("netcheck v2.3 开始扫描", "#2563eb")
        self.append_output(f"目标: {host}", "#6b7280")
        self.append_output("=" * 60, "#1e3a5f\n")

        options = {
            "protocol": self.protocol_combo.currentText().lower(),
            "timeout": self.timeout_spin.value(),
            "scan": self.scan_check.isChecked(),
            "os_detect": self.os_check.isChecked(),
            "waf_detect": self.waf_check.isChecked(),
            "full": self.full_check.isChecked(),
            "scan_timeout": 0.8,
            "workers": 100,
            "waf_ports": [p.value() for p, _ in self.waf_port_rows],
            "waf_expected": {p.value(): proto.currentText() for p, proto in self.waf_port_rows}
        }

        port = int(port_text.split(',')[0].strip())

        self.scan_thread = ScanThread(host, port, options)
        self.scan_thread.progress.connect(self.on_progress)
        self.scan_thread.progress_percent.connect(self.on_progress_percent)
        self.scan_thread.result_ready.connect(self.on_result_ready)
        self.scan_thread.finished.connect(self.on_scan_finished)
        self.scan_thread.start()

        self.statusBar().showMessage("扫描中...")

    def stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.terminate()
            self.append_output("\n[扫描已停止]", "#f59e0b")
            self.statusBar().showMessage("扫描已停止")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def on_progress(self, msg):
        self.append_output(msg, "#60a5fa")
        self.statusBar().showMessage(msg)

    def on_progress_percent(self, value):
        self.progress_bar.setValue(value)

    def on_result_ready(self, result):
        self.current_result = result
        self.progress_bar.setFormat("%p% - 完成")
        self.progress_bar.setValue(100)

        self.append_output("\n" + "=" * 60, "#1e3a5f")
        self.append_output("扫描结果", "#2563eb")
        self.append_output("=" * 60, "#1e3a5f")

        # DNS
        dns = result.get("dns", {})
        color = "#22c55e" if dns.get("success") else "#ef4444"
        self.append_output(f"[DNS] {dns.get('message', '')}", color)
        for ip in dns.get("ips", []):
            self.append_output(f"    → {ip}", "#6b7280")

        # Ping
        ping = result.get("ping", {})
        color = "#22c55e" if ping.get("success") else "#ef4444"
        self.append_output(f"[Ping] {ping.get('message', '')}", color)

        # 端口
        port_data = result.get("port", {})
        port_info = port_data.get("data", {})
        status = "开放" if port_data.get("success") else "关闭/被过滤"
        color = "#22c55e" if port_data.get("success") else "#ef4444"
        self.append_output(f"[端口] {status}", color)
        if port_info.get("response_time"):
            self.append_output(f"    响应时间: {port_info['response_time']:.2f}ms", "#6b7280")
        self.append_output(f"    协议: {port_info.get('protocol', 'unknown')}", "#6b7280")

        # WAF 检测结果
        self.display_waf_result(result.get("waf_result", {}))

        # 开放端口
        open_ports = result.get("open_ports", [])
        if open_ports:
            self.append_output(f"\n[端口扫描] 发现 {len(open_ports)} 个开放端口:", "#f59e0b")
            for p in open_ports:
                rtt = f"{p['response_time']:.1f}ms" if p.get('response_time') else "-"
                self.append_output(f"    {p['port']:>5}  {p['service']:<15} {p['protocol']:<10} {rtt}", "#6b7280")

            # 更新端口表格
            self.port_table.setRowCount(len(open_ports))
            for i, p in enumerate(open_ports):
                self.port_table.setItem(i, 0, QTableWidgetItem(str(p["port"])))
                self.port_table.setItem(i, 1, QTableWidgetItem(p.get("service", "")))
                self.port_table.setItem(i, 2, QTableWidgetItem(p.get("protocol", "")))
                rtt = f"{p['response_time']:.1f}ms" if p.get("response_time") else "-"
                self.port_table.setItem(i, 3, QTableWidgetItem(rtt))
                http_status = str(p.get("http_status")) if p.get("http_status") else "-"
                self.port_table.setItem(i, 4, QTableWidgetItem(http_status))
                self.port_table.setItem(i, 5, QTableWidgetItem(p.get("server", "")))
                # WAF 标记
                if p.get("is_waf_port"):
                    self.port_table.setItem(i, 6, QTableWidgetItem("🛡️"))
                else:
                    self.port_table.setItem(i, 6, QTableWidgetItem("-"))

        # 系统指纹
        os_guess = result.get("os_guess", {})
        if os_guess:
            self.append_output(f"\n[系统指纹] {os_guess.get('os', 'Unknown')} (置信度: {os_guess.get('confidence', 0)}%)", "#8b5cf6")
            for ev in os_guess.get("evidence", []):
                self.append_output(f"    • {ev.get('来源')}: {ev.get('值')} → {ev.get('推断')}", "#6b7280")

            os_display = f"操作系统推断: {os_guess.get('os', 'Unknown')}\n"
            os_display += f"置信度: {os_guess.get('confidence', 0)}%\n\n证据:\n"
            for ev in os_guess.get("evidence", []):
                os_display += f"  • {ev.get('来源')}: {ev.get('值')}\n    推断: {ev.get('推断')}\n\n"
            self.os_text.setPlainText(os_display)

        # JSON
        json_output = json.dumps(result, indent=2, ensure_ascii=False)
        self.json_text.setPlainText(json_output)

        self.tabs.setCurrentIndex(0)

    def display_waf_result(self, waf_result):
        """显示 WAF 检测结果"""
        self.waf_text.clear()

        if not waf_result:
            self.waf_text.setPlainText("WAF 专项检测未启用")
            return

        display = "=" * 50 + "\n"
        display += "🛡️ WAF 专项检测结果 (5677/5678/5679)\n"
        display += "=" * 50 + "\n\n"

        for port, info in waf_result.get("ports", {}).items():
            expected = info.get("expected_protocol", "unknown")
            detected = info.get("detected_protocol", "unknown")
            status = info.get("status", "unknown")
            http_status = info.get("http_status")
            is_anomaly = info.get("is_anomaly", False)

            display += f"端口 {port}:\n"
            display += f"  预期协议: {expected.upper()}\n"
            display += f"  检测协议: {detected.upper()}\n"
            display += f"  状态: {status}\n"

            if http_status:
                display += f"  HTTP状态: {http_status}\n"

            if is_anomaly:
                display += f"  ⚠️ 异常: {info.get('description', '')}\n"
                display += f"  💡 建议: {info.get('description', '')}\n"

            display += "\n"

        # 异常汇总
        anomalies = waf_result.get("anomalies", [])
        if anomalies:
            display += "=" * 50 + "\n"
            display += f"⚠️ 检测到 {len(anomalies)} 个配置异常:\n"
            display += "=" * 50 + "\n\n"

            for i, anomaly in enumerate(anomalies, 1):
                display += f"{i}. 端口 {anomaly['port']}\n"
                display += f"   问题: {anomaly['description']}\n"
                display += f"   建议: {anomaly.get('suggestion', '')}\n\n"

        display += f"\n总结: {waf_result.get('summary', '')}\n"

        self.waf_text.setPlainText(display)

        # 如果有异常，高亮显示
        if anomalies:
            self.waf_text.setStyleSheet("QTextEdit { background-color: #fef2f2; }")
        else:
            self.waf_text.setStyleSheet("QTextEdit { background-color: #f0fdf4; }")

    def on_scan_finished(self):
        self.append_output("\n" + "=" * 60, "#1e3a5f")
        self.append_output("扫描完成", "#22c55e")
        self.append_output("=" * 60, "#1e3a5f")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setFormat("%p% - 完成")
        self.statusBar().showMessage("扫描完成")

    def clear_results(self):
        self.output_text.clear()
        self.port_table.setRowCount(0)
        self.waf_text.clear()
        self.waf_text.setStyleSheet("")
        self.os_text.clear()
        self.json_text.clear()
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("%p%")
        self.current_result = {}
        self.statusBar().showMessage("已清除")

    def export_json(self):
        if not self.current_result:
            QMessageBox.warning(self, "无数据", "请先执行扫描")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "导出JSON", "netcheck_result.json", "JSON Files (*.json)"
        )
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.current_result, f, indent=2, ensure_ascii=False)
            QMessageBox.information(self, "导出成功", f"结果已保存到:\n{filename}")


def main():
    if not PYQT5_AVAILABLE:
        print("错误: PyQt5 未安装")
        print("请运行: pip install PyQt5")
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    font = QFont("SF Mono", 11)
    app.setFont(font)

    window = NetcheckGUI()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
