#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
syslog_sink —— 零依赖 UDP syslog 收集器，把设备实时发来的日志落成文件

设备侧（华为 VRP）通常这样配：
    info-center enable
    info-center loghost 192.168.1.10            # 收日志的机器
    info-center source default channel 2 log level information

本机启动：
    python tools/syslog_sink.py --out logs/router1.log --port 5140
    # 端口 <1024 在 Windows 上需要管理员权限，建议用 5140；
    # 防火墙要放行 UDP 入站，否则设备发过来会被丢弃。

收到的是原样文本，落盘后直接交给主程序：
    python -m netpatrol analyze logs/router1.log --html

注意：eNSP 的拓扑是完全虚拟的，路由器发不到宿主机上。要在仿真里用这条路，
得加一个 Cloud 节点并绑定物理网卡；否则请直接在设备上用 display logbuffer
复制日志，再 analyze 那个文件。
"""

from __future__ import annotations

import argparse
import socket
import sys
from datetime import datetime
from pathlib import Path

MAX_BYTES = 64 * 1024 * 1024  # 防止无人值守时把磁盘写满


def decode(data: bytes) -> str:
    """设备语言环境不统一，先 UTF-8 再 GBK，最后兜底替换。"""
    for enc in ("utf-8", "gbk"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def main() -> int:
    ap = argparse.ArgumentParser(description="收集设备 syslog 到文件（UDP）")
    ap.add_argument("--port", type=int, default=5140, help="监听端口，默认 5140")
    ap.add_argument("--bind", default="0.0.0.0", help="监听地址，默认 0.0.0.0")
    ap.add_argument("--out", required=True, help="输出文件路径")
    ap.add_argument("--append", action="store_true", help="追加而不是覆盖")
    args = ap.parse_args()

    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((args.bind, args.port))
    except OSError as e:
        print(f"[!] 无法监听 {args.bind}:{args.port} -> {e}", file=sys.stderr)
        print("    端口被占用或 <1024 需要管理员权限", file=sys.stderr)
        return 2

    mode = "ab" if args.append else "wb"
    total = size = 0
    senders: set[str] = set()
    print(f"[*] 监听 udp://{args.bind}:{args.port} -> {path}（Ctrl+C 结束）")
    try:
        with open(path, mode, encoding=None) as fh:
            if not args.append:
                fh.write(f"# captured by syslog_sink {datetime.now():%Y-%m-%d %H:%M:%S}\n".encode("utf-8"))
            while True:
                data, addr = sock.recvfrom(65535)
                if not data.strip():
                    continue
                total += 1
                senders.add(addr[0])
                text = decode(data).rstrip("\r\n")
                for line in text.splitlines() or [""]:
                    fh.write((line + "\n").encode("utf-8"))
                fh.flush()
                size = path.stat().st_size
                print(f"  [{addr[0]}] {text[:110]}", flush=True)
                if size >= MAX_BYTES:
                    print(f"[!] 已达 {size // 1048576} MB 上限，停止收集", file=sys.stderr)
                    break
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        print(f"[*] 结束：{total} 条报文，来自 {len(senders) or 0} 个源 -> {path}"
              f"{'（' + ', '.join(sorted(senders)) + '）' if senders else ''}")
        print(f"    下一步：python -m netpatrol analyze {path} --html")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
