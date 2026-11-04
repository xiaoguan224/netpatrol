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

# 华为 VRP 的字段顺序（《信息的输出格式》）：
#   时间戳 [时区] 主机名 [IPv4] %%版本 模块/级别/名称(类别)[序号]: 描述
# 时间戳共 5 种：date（中文环境 yyyy/mm/dd、英文环境 mm dd yyyy）、short-date（无年份）、
# format-date（YYYY-MM-DD）、boot（相对开机毫秒，无法定位绝对时间，本工具不认）、none。
# display logbuffer 的终端回显会给每行加 '%' 前缀，Trap 行加 '#'；发往日志主机时加 '<PRI>'。
TS_ALT = (
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}\s+\d{1,2}:\d{2}:\d{2}"      # Jul 10 2026 08:23:45
    r"|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}\s+\d{4}"     # Jul 10 08:23:45 2026
    r"|\d{4}/\d{1,2}/\d{1,2}\s+\d{1,2}:\d{2}:\d{2}"               # 2026/07/10 08:23:45 date
    r"|\d{4}-\d{2}-\d{2}[T ]\d{1,2}:\d{2}:\d{2}"                  # 2026-07-10 08:23:45 format-date
    r"|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}"             # Jul 10 08:23:45 short-date
)

# VRP 分隔符是两个百分号，所以 TS_ALT 用字符串相加注入而不是 % 格式化，否则 "%%" 会被压成 "%"
HUAWEI_RE = re.compile(
    r"""
    ^(?:\[(?P<brackhost>[^\]]+)\])?\s*                           # 可选 [R1] 前缀
    (?:<(?P<pri>\d{1,3})>)?\s*                                   # 可选 <PRI>（发往日志主机）
    [\#%]?\s*                                                    # 可选 # Trap / % 缓冲区标记
    (?P<ts>(?:""" + TS_ALT + r""")(?:[.:]\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?)\s+
    (?P<host>\S+)(?:\s+(?P<ipv4>(?:\d{1,3}\.){3}\d{1,3}))?\s+
    %%\d{2}(?P<module>[A-Za-z0-9_-]+)/(?P<sev>[0-7])/(?P<code>[A-Za-z0-9_-]+)
    (?:\((?P<ctx>[A-Za-z0-9]{1,4})\))?(?:\[(?P<seq>\d+)\])?
    \s*[:：]\s*
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

# 不是日志的行：设备提示符、More 分页符、VRP 版本横幅、CLI 报错——跳过而非算解析失败
SKIP_RE = re.compile(r"""
    ^\s*\#                                      # logbuffer 分隔符、Trap 头、采集器注释
    |^\s*<[\w.-]+>\s*\S*                        # <R1>display logbuffer
    |^\s*-+\s*[Mm]ore\s*-+                      # ---- More ----
    |^\s*%\s+\S                                 # % Unknown command
    |^\s*(Huawei\s+Versatile|VRP\s*\(R\)|Copyright\s*\(C\)|Compiled\s+at|Software)
    |^\s*(Log\s+buffer|Logging\s+buffer|More\s+records|Zipped|Info-?center|Current\s+logging|Last\s+logging)
    |^\s*(Allowed\s+max|Actual\s+buffer|Channel\s+number|Dropped|Overwritten|Current)\s
    |^\s*(Error|Warning):\s
    """, re.VERBOSE)

TS_FORMATS = [
    "%b %d %Y %H:%M:%S", "%b  %d %Y %H:%M:%S",
    "%b %d %H:%M:%S %Y", "%b  %d %H:%M:%S %Y",
    "%b %d %H:%M:%S", "%b  %d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
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


def _strip_tz_ms(raw: str) -> str:
    """去掉时区与毫秒，只留可判断「有没有年份」的部分。"""
    raw = re.sub(r"(Z|[+-]\d{2}(?::?\d{2})?)$", "", raw.strip())
    return re.sub(r"[.:]\d{1,6}(?=\s|$)", "", raw)


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
# 模块名取自真实 VRP 设备（AR/USG/S 系列）日志里出现过的 ModuleName，不是穷举
RULES = [
    ("接口链路", {"IFNET", "LINK", "ETH", "ETHL2", "BFD", "TRUNK", "PHY", "LAN"},
     r"LINK_STATE|UPDOWN|up\b|down\b|状态", "接口物理/协议状态变化"),
    ("认证安全", {"SSH2", "TELNET", "FTP", "FTPC", "HTTP", "AAA", "SECE", "SEC", "AUTH",
                  "LOCAL", "SFTP", "RADIUS", "TACACS", "TACPLUS"},
     r"FAIL|DENY|ATTACK|BRUTEFORC|拒绝|失败|攻击", "认证失败/安全攻击事件"),
    ("路由协议", {"OSPF", "BGP", "STP", "RIP", "ISIS", "VRRP", "ARP", "ND", "LSM"},
     r"NBR|NEIGHBOR|ADJACEN|CHANGE|TOPOLOG|CONFLICT|邻居|冲突|切换|主备", "路由/二三层协议状态变化"),
    ("系统资源", {"SYS", "CPU", "VOSCPU", "MEM", "DEV", "O&M", "POWER", "FAN", "TEMP",
                  "SYSM", "HRD", "SDM", "CPCAR", "OAM", "GTL", "LICENSE"},
     r"USAGE|HIGH|REBOOT|ALARM|THRESHOLD|SWITCH_OVER|使用率|重启|告警|切换", "设备资源与环境告警"),
    ("配置变更", {"SHELL", "CFGC", "SYS", "SYSM", "NETCONF", "CMDRECORD", "CFM"},
     r"CMDRECORD|CONFIG|COMMIT|ROLLBACK|save|配置|命令|Command=", "配置/命令操作记录"),
    ("VPN隧道", {"IPSEC", "L2TP", "VPN", "IKE", "IKEV2", "DSVPN", "GRE", "TUNNEL"},
     r"TUNNEL|SA|ESTABLISH|TEARDOWN|隧道", "VPN 隧道建立/拆除"),
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
    ev = _parse_huawei(line, line_no, default_year) or _parse_syslog(line, line_no)
    if ev is not None:
        ev.template = make_template(ev.msg)
        classify(ev)
    return ev


def _parse_huawei(line: str, line_no: int, default_year: int) -> Optional[Event]:
    m = HUAWEI_RE.match(line)
    if not m:
        return None
    ts_raw = m.group("ts")
    if re.search(r"\d{4}", _strip_tz_ms(ts_raw)) is None:  # short-date 缺年份则补
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


WRAP_WIDTH = 80  # eNSP/VRP 终端列宽：日志超过它会被硬折成两行，续行不带时间戳


def _append_wrap(tail: str, cont: str) -> str:
    """拼回被终端折断的一行。VRP 断在词中间时不加空格，断在空格后也不重复补空格。"""
    if tail.endswith((" ", "\t")) and cont.startswith((" ", "\t")):
        return tail.rstrip() + " " + cont.lstrip()
    return tail + cont


def load_events(paths: Iterable[Path]) -> tuple[list[Event], list[str], list[str]]:
    """返回 (事件, 未识别行, 跳过或合并的行)。

    从终端复制出来的 display logbuffer 往往混着提示符、More 分页符、缓冲区统计头、VRP 版本横幅，
    这些本来就不是日志；长日志还会被终端宽度硬折成两行。三类都不该算解析失败，所以单独记账。
    """
    events: list[Event] = []
    unparsed: list[str] = []
    skipped: list[str] = []
    for p in paths:
        text = Path(p).read_text(encoding="utf-8", errors="replace")
        year_match = re.search(r"\b(20\d{2})\b", text[:4000])
        default_year = int(year_match.group(1)) if year_match else datetime.now().year
        pending: Optional[Event] = None
        for i, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            ev = parse_line(line, i, default_year)
            if ev is not None:
                events.append(ev)
                pending = ev
                continue
            if SKIP_RE.match(line):
                skipped.append(f"{p.name}:{i}: {line.strip()[:90]}")
                continue
            cont = line.rstrip()
            if pending is not None and len(pending.raw) >= WRAP_WIDTH:
                pending.raw = _append_wrap(pending.raw, cont)
                pending.msg = _append_wrap(pending.msg, cont)
                pending.template = make_template(pending.msg)
                classify(pending)
                skipped.append(f"{p.name}:{i}: [折行→第{pending.line_no}行] {cont[:60]}")
                continue
            unparsed.append(f"{p.name}:{i}: {line.strip()[:90]}")
    events.sort(key=lambda e: (e.ts or datetime.min, e.line_no))
    return events, unparsed, skipped
