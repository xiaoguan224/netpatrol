#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netpatrol —— 网络设备日志智能巡检工具（零第三方依赖）

流程：日志解析 → 规则分类 → 统计异常检测 → 自动生成巡检报告(Markdown/HTML)

用法：
    python -m netpatrol demo                       # 用内置样例日志跑一遍完整流程
    python -m netpatrol analyze router.log -o out  # 分析自己的日志文件
    python -m netpatrol analyze a.log b.log --html # 多文件 + 输出 HTML 报告
"""

from __future__ import annotations

import argparse
import html
import json
import math
import os
import re
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, Optional

__version__ = "1.0.0"

# --------------------------------------------------------------------------
# 1. 解析层：兼容华为/eNSP 与常见 syslog 变体
# --------------------------------------------------------------------------

# 华为风格:  Jul 10 2026 08:23:45:100 R1 %%10IFNET/4/LINK_STATE(d):GigabitEthernet0/0/1 status UP
# 也接受:    [R1]Jul 10 08:23:45 2026 R1 %%10SSH2/4/SFTP_AUTH_FAIL: ...
HUAWEI_RE = re.compile(
    r"""
    ^(?:\[(?P<brackhost>[^\]]+)\])?\s*                       # 可选 [R1] 前缀
    (?P<ts>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})(?:[.:]\d{1,6}(?=\s+\S|$))?)\s+
    (?P<host>\S+)\s+
    %%\d{2}(?P<module>[A-Za-z0-9_-]+)/(?P<sev>[0-7])/(?P<code>[A-Za-z0-9_-]+)
    (?:\((?P<ctx>[^)]*)\))?\s*[:：]\s*
    (?P<msg>.*)$
    """,
    re.VERBOSE,
)

# 通用 syslog: 2026-07-10T08:23:45+08:00 SW1 10.0.0.1 %LINK-3-UPDOWN: ...
SYSLOG_RE = re.compile(
    r"""
    ^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+
    (?P<host>\S+)(?:\s+\d+\.\d+\.\d+\.\d+)?\s+
    %?(?P<module>[A-Z0-9_-]+)?-?(?P<sev>[0-7])?-?(?P<code>[A-Z0-9_-]+)?[:：\-]\s*
    (?P<msg>.*)$
    """,
    re.VERBOSE,
)

TS_FORMATS = [
    "%b %d %Y %H:%M:%S", "%b  %d %Y %H:%M:%S",
    "%b %d %H:%M:%S %Y", "%b  %d %H:%M:%S %Y",
    "%b %d %H:%M:%S", "%b  %d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
]

SEVERITY_NAME = {0: "紧急", 1: "告警", 2: "严重", 3: "错误", 4: "警告", 5: "信息", 6: "调试", 7: "调试"}
SEVERITY_LEVEL = {0: "P0", 1: "P0", 2: "P1", 3: "P1", 4: "P2", 5: "P3", 6: "P4", 7: "P4"}


def parse_ts(raw: str) -> Optional[datetime]:
    raw = raw.strip()
    raw = re.sub(r"(Z|[+-]\d{2}(?::?\d{2})?)$", "", raw)
    m = re.search(r"(?<!\d)(\d{1,2}:\d{2}:\d{2})[.:](\d{1,6})(?!\d)", raw)  # 毫秒分隔符可能是点或冒号
    if m:
        raw = raw.replace(m.group(0), m.group(1))
    else:
        raw = re.sub(r"\.\d{1,6}(?=\s|$)", "", raw)
    raw = re.sub(r"\s+", " ", raw)
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


@dataclass
class Event:
    ts: Optional[datetime]
    host: str
    module: str
    sev: int
    code: str
    msg: str
    raw: str
    line_no: int = 0
    category: str = "其他"
    rule: str = ""
    template: str = ""

    @property
    def sev_name(self) -> str:
        return SEVERITY_NAME.get(self.sev, "未知")

    @property
    def priority(self) -> str:
        return SEVERITY_LEVEL.get(self.sev, "P4")


IFACE_RE = re.compile(r"(GigabitEthernet|GE|XGigabitEthernet|Eth-Trunk|Vlanif|Serial|LoopBack|Bri)\d[\d/.]*", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_RE = re.compile(r"\b[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}\b|\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.I)
NUM_RE = re.compile(r"\b\d+\b")


def make_template(msg: str) -> str:
    t = MAC_RE.sub("<MAC>", msg)
    t = IFACE_RE.sub("<IFACE>", t)
    t = IP_RE.sub("<IP>", t)
    t = re.sub(r"\b\d{4}-\d{2}-\d{2}[T ]?\d{2}:\d{2}:\d{2}\b", "<TIME>", t)
    t = NUM_RE.sub("<N>", t)
    return t


# 规则库：(类别, 匹配模块, 匹配码/消息关键字, 说明)
RULES = [
    ("接口链路", {"IFNET", "LINK", "ETH"}, r"LINK_STATE|UPDOWN|up\b|down\b|状态", "接口物理/协议状态变化"),
    ("认证安全", {"SSH2", "TELNET", "FTP", "HTTP", "AAA", "SECE", "AUTH"}, r"FAIL|DENY|ATTACK|BRUTEFORC|拒绝|失败|攻击", "认证失败/安全攻击事件"),
    ("路由协议", {"OSPF", "BGP", "STP", "RIP", "ISIS", "VRRP"}, r"NBR|NEIGHBOR|ADJACEN|CHANGE|TOPOLOG|邻居|切换|主备", "路由/二三层协议状态变化"),
    ("系统资源", {"SYS", "CPU", "MEM", "DEV", "O&M", "POWER", "FAN", "TEMP"}, r"USAGE|HIGH|REBOOT|ALARM|THRESHOLD|使用率|重启|告警", "设备资源与环境告警"),
    ("配置变更", {"SHELL", "CFGC", "SYS", "NETCONF"}, r"CMDRECORD|CONFIG|COMMIT|ROLLBACK|save|配置|命令", "配置/命令操作记录"),
    ("VPN隧道", {"IPSEC", "L2TP", "VPN", "IKE"}, r"TUNNEL|SA|ESTABLISH|TEARDOWN|隧道", "VPN 隧道建立/拆除"),
]


def classify(ev: Event) -> Event:
    hay = f"{ev.code} {ev.msg}"
    for cat, modules, pattern, _desc in RULES:
        if ev.module.upper() in modules or re.search(pattern, hay, re.I):
            if ev.module.upper() in modules:
                ev.category, ev.rule = cat, _desc
                return ev
    for cat, _m, pattern, desc in RULES:
        if re.search(pattern, hay, re.I):
            ev.category, ev.rule = cat, desc
            return ev
    return ev


def parse_line(line: str, line_no: int, default_year: int) -> Optional[Event]:
    line = line.rstrip("\n")
    if not line.strip():
        return None
    ev = _parse_huawei(line, line_no) or _parse_syslog(line, line_no)
    if ev is not None:
        ev.template = make_template(ev.msg)
        classify(ev)
    return ev


def _parse_huawei(line: str, line_no: int) -> Optional[Event]:
    m = HUAWEI_RE.match(line)
    if not m:
        return None
    ts_raw = m.group("ts")
    if re.search(r"\b\d{4}\b", ts_raw) is None:  # 缺年份则补
        ts_raw = f"{ts_raw} {default_year}"
    return Event(ts=parse_ts(ts_raw), host=m.group("host"), module=m.group("module"),
                 sev=int(m.group("sev")), code=m.group("code"), msg=m.group("msg"),
                 raw=line, line_no=line_no)


def _parse_syslog(line: str, line_no: int) -> Optional[Event]:
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    return Event(ts=parse_ts(m.group("ts")), host=m.group("host"),
                 module=(m.group("module") or "GEN").upper(),
                 sev=int(m.group("sev")) if m.group("sev") else 5,
                 code=m.group("code") or "-", msg=m.group("msg"), raw=line, line_no=line_no)


def load_events(paths: Iterable[Path]) -> tuple[list[Event], list[str]]:
    events: list[Event] = []
    unparsed: list[str] = []
    for p in paths:
        text = Path(p).read_text(encoding="utf-8", errors="replace")
        year_match = re.search(r"\b(20\d{2})\b", text[:4000])
        default_year = int(year_match.group(1)) if year_match else datetime.now().year
        for i, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            ev = parse_line(line, i, default_year)
            if ev is None:
                unparsed.append(f"{p.name}:{i}: {line.strip()[:90]}")
                continue
            ev.template = make_template(ev.msg)
            classify(ev)
            events.append(ev)
    events.sort(key=lambda e: (e.ts or datetime.min, e.line_no))
    return events, unparsed
