---
name: ida-mcp-restart
description: IDA Pro MCP 连接重启指南。当 IDA MCP HTTP Server 不可用时，使用此 skill 重启连接。包含自动重启和手动重启方法。
---

# IDA Pro MCP 重启指南

当遇到 "IDA Pro HTTP 连接失败" 错误时，使用此指南重启 MCP 连接。

## 架构说明

```
┌─────────────────────────────────────────────────────────────┐
│                    IDA Pro                                   │
│                                                              │
│   ┌──────────────────┐      ┌──────────────────┐            │
│   │ Control Channel  │      │   HTTP Server    │            │
│   │   端口 13400+     │      │   端口 13337      │            │
│   │   (自动启动)      │◄────►│   (按需启动)      │            │
│   └──────────────────┘      └──────────────────┘            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
                              ▲
                              │ HTTP 连接
                              │
┌─────────────────────────────────────────────────────────────┐
│                    Claude Code (MCP)                         │
│                                                              │
│   自动发现 → 自动启动 HTTP Server → 连接                      │
└─────────────────────────────────────────────────────────────┘
```

## 重启方法

### 方法 1: 自动重启 (推荐)

MCP Server 会自动通过控制通道启动 HTTP Server，通常无需手动操作。

如果自动启动失败，尝试以下方法。

### 方法 2: 手动启动 HTTP Server

**在 IDA Pro 中:**

| 平台 | 快捷键 |
|------|--------|
| macOS | `Edit → Plugins → MCP (Ctrl+Option+M)` |
| Windows/Linux | `Edit → Plugins → MCP (Ctrl+Alt+M)` |

### 方法 3: 通过 Python 脚本启动

运行以下 Python 脚本:

```python
import socket
import json
import os
from pathlib import Path

# 1. 获取 IDA 实例信息
instances_dir = Path.home() / ".ida-mcp" / "instances"

if not instances_dir.exists():
    print("❌ 没有发现 IDA 实例注册目录")
    print("   请先启动 IDA Pro 并打开一个数据库")
    exit(1)

# 2. 读取第一个实例
instance_files = sorted(instances_dir.glob("*.json"))
if not instance_files:
    print("❌ 没有发现 IDA 实例")
    exit(1)

with open(instance_files[0]) as f:
    instance = json.load(f)

print(f"📋 实例: {instance['database']}")
print(f"📋 控制端口: {instance['control_port']}")
print(f"📋 HTTP 端口: {instance['http_port']}")

# 3. 发送 START_HTTP 命令
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect(('127.0.0.1', instance['control_port']))
    s.send(b'START_HTTP')
    response = s.recv(4096).decode()
    s.close()

    result = json.loads(response)
    if result.get('status') == 'ok':
        print(f"✅ HTTP Server 启动成功!")
        print(f"   端口: {result.get('http_port', 13337)}")
    else:
        print(f"❌ 启动失败: {result.get('message')}")
except Exception as e:
    print(f"❌ 连接失败: {e}")
    print("   请检查 IDA Pro 是否正在运行")
```

### 方法 4: 检查服务状态

**发送 STATUS 命令:**

```python
import socket
import json
from pathlib import Path

instances_dir = Path.home() / ".ida-mcp" / "instances"
instance_files = sorted(instances_dir.glob("*.json"))

if instance_files:
    with open(instance_files[0]) as f:
        instance = json.load(f)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect(('127.0.0.1', instance['control_port']))
    s.send(b'STATUS')
    response = s.recv(4096).decode()
    s.close()

    print(json.dumps(json.loads(response), indent=2))
```

**使用命令行检查:**

```bash
# 检查实例注册
ls ~/.ida-mcp/instances/

# 查看实例详情
cat ~/.ida-mcp/instances/*.json

# 检查端口占用
lsof -i :13337  # HTTP 端口
lsof -i :13400  # 控制端口
```

## 控制命令列表

| 命令 | 功能 | 响应示例 |
|------|------|----------|
| `PING` | 健康检查 | `{"status": "ok", "message": "pong"}` |
| `START_HTTP` | 启动 HTTP Server | `{"status": "ok", "http_port": 13337}` |
| `STOP_HTTP` | 停止 HTTP Server | `{"status": "ok"}` |
| `STATUS` | 获取实例状态 | `{"status": "ok", "data": {...}}` |
| `SHUTDOWN` | 关闭控制通道 | `{"status": "ok", "message": "shutting down"}` |

## 故障排除

### 问题 1: 未发现 IDA 实例

**原因:** IDA Pro 未启动或 MCP 插件未加载

**解决:**
1. 启动 IDA Pro
2. 打开一个数据库文件 (.idb/.i64)
3. 等待 MCP 插件自动注册 (查看输出窗口的 `[MCP]` 日志)

### 问题 2: 控制通道无响应

**原因:** IDA 进程崩溃或控制线程卡死

**解决:**
1. 检查 IDA 进程是否存活: `ps aux | grep ida`
2. 如果进程存在但无响应，重启 IDA Pro
3. 删除过期的实例注册文件: `rm ~/.ida-mcp/instances/*.json`

### 问题 3: HTTP Server 启动失败

**原因:** 端口被占用或权限问题

**解决:**
1. 检查端口占用: `lsof -i :13337`
2. 如果被占用，终止占用进程或修改端口
3. 检查防火墙设置

### 问题 4: 连接超时

**原因:** 网络问题或 HTTP Server 崩溃

**解决:**
1. 发送 `STATUS` 命令检查状态
2. 发送 `STOP_HTTP` 然后 `START_HTTP` 重启
3. 如果仍然失败，重启 IDA Pro

## 一键重启脚本

保存为 `restart_ida_mcp.py`:

```python
#!/usr/bin/env python3
"""IDA MCP 一键重启脚本"""

import socket
import json
import sys
from pathlib import Path

def restart_ida_mcp():
    instances_dir = Path.home() / ".ida-mcp" / "instances"

    # 查找实例
    instance_files = sorted(instances_dir.glob("*.json"))
    if not instance_files:
        print("❌ 未发现 IDA 实例，请先启动 IDA Pro")
        return False

    with open(instance_files[0]) as f:
        instance = json.load(f)

    print(f"📋 连接实例: {instance['database']}")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect(('127.0.0.1', instance['control_port']))

        # 停止 HTTP Server
        s.send(b'STOP_HTTP')
        s.recv(4096)

        # 启动 HTTP Server
        s.send(b'START_HTTP')
        response = json.loads(s.recv(4096).decode())
        s.close()

        if response.get('status') == 'ok':
            print(f"✅ HTTP Server 重启成功! 端口: {response.get('http_port')}")
            return True
        else:
            print(f"❌ 重启失败: {response.get('message')}")
            return False

    except Exception as e:
        print(f"❌ 连接失败: {e}")
        return False

if __name__ == "__main__":
    sys.exit(0 if restart_ida_mcp() else 1)
```

运行:
```bash
python3 restart_ida_mcp.py
```

## 端口说明

| 端口 | 用途 | 启动方式 |
|------|------|----------|
| 13337 | HTTP Server (MCP 请求) | 控制命令或手动 |
| 13400+ | Control Channel (控制命令) | IDA 启动时自动 |
