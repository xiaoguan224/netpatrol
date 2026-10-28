#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""统计异常检测层：不依赖任何 ML 库，用滑动窗口 + 基线离群 + 模板新颖度三类方法。"""

from __future__ import annotations

import math
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from .core import Event


@dataclass
class Finding:
    kind: str            # 异常类型
    severity: str        # P0-P3
    target: str          # 涉及对象（设备/接口/IP）
    count: int
    first: Optional[datetime]
    last: Optional[datetime]
    detail: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "kind": self.kind, "severity": self.severity, "target": self.target,
            "count": self.count,
            "first": self.first.isoformat(sep=" ") if self.first else None,
            "last": self.last.isoformat(sep=" ") if self.last else None,
            "detail": self.detail, "evidence": self.evidence[:5],
        }


IFACE_RE = re.compile(r"(GigabitEthernet|GE|XGigabitEthernet|Eth-Trunk|Vlanif|Serial)\d[\d/.]*", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SEV_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}


def _windowed_bursts(events: list[Event], window: timedelta, min_count: int):
    """滑动窗口聚合：返回 (窗口内事件列表) 的极大簇。"""
    pts = [e for e in events if e.ts]
    pts.sort(key=lambda e: e.ts)
    used = [False] * len(pts)
    clusters = []
    i = 0
    while i < len(pts):
        if used[i]:
            i += 1
            continue
        j = i
        cluster = [pts[i]]
        used[i] = True
        k = i + 1
        while k < len(pts) and pts[k].ts - cluster[0].ts <= window:
            cluster.append(pts[k])
            used[k] = True
            k += 1
        if len(cluster) >= min_count:
            clusters.append(cluster)
            i = k
        else:
            i += 1
    return clusters


def detect_flapping(events: list[Event], window_min: int = 5, min_transitions: int = 4) -> list[Finding]:
    """接口抖动：同一接口在窗口内状态翻转次数过多。"""
    groups: dict[tuple, list[Event]] = defaultdict(list)
    for e in events:
        if e.category != "接口链路":
            continue
        m = IFACE_RE.search(e.msg)
        if not m:
            continue
        groups[(e.host, m.group(0).upper())].append(e)
    out = []
    win = timedelta(minutes=window_min)
    for (host, iface), evs in groups.items():
        for cluster in _windowed_bursts(evs, win, min_transitions):
            states = {("UP" if re.search(r"up\b", c.msg, re.I) and not re.search(r"down", c.msg, re.I) else "DOWN") for c in cluster}
            if len(states) < 2:
                continue
            out.append(Finding(
                kind="接口抖动", severity="P1", target=f"{host}/{iface}", count=len(cluster),
                first=cluster[0].ts, last=cluster[-1].ts,
                detail=f"{window_min} 分钟内状态翻转 {len(cluster)} 次（UP/DOWN 交替），疑似链路不稳定或协商问题",
                evidence=[f"{c.ts:%m-%d %H:%M:%S} {c.msg[:70]}" for c in cluster],
            ))
            break  # 同一接口只报最严重一簇
    return out


def detect_bruteforce(events: list[Event], window_min: int = 10, min_fail: int = 5) -> list[Finding]:
    """认证爆破：同一源 IP 在窗口内认证失败次数过多。"""
    groups: dict[tuple, list[Event]] = defaultdict(list)
    for e in events:
        if e.category != "认证安全":
            continue
        if not re.search(r"fail|deny|拒绝|失败|brute", e.msg + e.code, re.I):
            continue
        ips = IP_RE.findall(e.raw)
        src = next((ip for ip in ips if ip != "127.0.0.1"), None)
        if not src:
            continue
        groups[(e.host, src)].append(e)
    out = []
    win = timedelta(minutes=window_min)
    for (host, src), evs in groups.items():
        for cluster in _windowed_bursts(evs, win, min_fail):
            users = sorted({mm.group(1) for c in cluster if (mm := re.search(r"user\s+(\S+)", c.msg, re.I))})
            out.append(Finding(
                kind="疑似暴力破解", severity="P0", target=f"{host} ← {src}", count=len(cluster),
                first=cluster[0].ts, last=cluster[-1].ts,
                detail=f"{window_min} 分钟内来自 {src} 的认证失败 {len(cluster)} 次"
                       + (f"，尝试用户名: {', '.join(users[:5])}" if users else ""),
                evidence=[f"{c.ts:%m-%d %H:%M:%S} {c.msg[:80]}" for c in cluster],
            ))
            break
    return out


def detect_burst(events: list[Event], bucket_min: int = 5, k: float = 3.0, min_count: int = 8) -> list[Finding]:
    """频率突增：以 bucket 分桶计数，超过 均值+kσ 判为异常（在线基线）。"""
    timed = [e for e in events if e.ts]
    if len(timed) < bucket_min * 2:
        return []
    t0 = timed[0].ts
    buckets: dict[int, list[Event]] = defaultdict(list)
    for e in timed:
        buckets[int((e.ts - t0).total_seconds() // (bucket_min * 60))].append(e)
    counts = {b: len(v) for b, v in buckets.items()}
    if len(counts) < 3:
        return []
    mean = statistics.fmean(counts.values())
    stdev = statistics.pstdev(list(counts.values())) or 0.001
    thr = mean + k * stdev
    out = []
    for b, evs in sorted(buckets.items()):
        if len(evs) >= min_count and len(evs) > thr:
            top = Counter(f"{e.module}/{e.code}" for e in evs).most_common(3)
            start = t0 + timedelta(minutes=bucket_min * b)
            out.append(Finding(
                kind="日志频率突增", severity="P2", target="、".join(h for h, _ in top),
                count=len(evs), first=evs[0].ts, last=evs[-1].ts,
                detail=f"{start:%m-%d %H:%M} 起 {bucket_min} 分钟内产生 {len(evs)} 条日志（基线均值 {mean:.1f}，阈值 {thr:.1f}），事件集中：{top}",
                evidence=[f"{c.ts:%H:%M:%S} {c.module}/{c.code}: {c.msg[:60]}" for c in evs[:6]],
            ))
    return out


def detect_novelty(events: list[Event], warmup: int = 20) -> list[Finding]:
    """模板新颖度：出现次数为 1 且带高危级别的事件模板，值得人工看一眼。"""
    tpl: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.sev <= 4:  # 警告及以上
            tpl[e.template].append(e)
    out = []
    for t, evs in tpl.items():
        if len(evs) == 1 and evs[0].sev <= 3:
            e = evs[0]
            out.append(Finding(
                kind="罕见错误模板", severity="P2", target=e.host, count=1,
                first=e.ts, last=e.ts,
                detail=f"全量日志中仅出现一次的高级别模板：{t[:90]}",
                evidence=[f"{e.ts:%m-%d %H:%M:%S} {e.msg[:90]}"],
            ))
    return out


def detect_offhours(events: list[Event], start_h: int = 0, end_h: int = 6) -> list[Finding]:
    """异常时段操作：凌晨时段出现的配置变更/命令记录。"""
    out = []
    for e in events:
        if not e.ts or e.category != "配置变更":
            continue
        if start_h <= e.ts.hour < end_h:
            out.append(Finding(
                kind="异常时段操作", severity="P1", target=e.host, count=1,
                first=e.ts, last=e.ts,
                detail=f"{e.ts:%H:%M} 出现配置/命令操作：{e.msg[:80]}",
                evidence=[e.raw[:120]],
            ))
    return out


def detect_protocol_resets(events: list[Event]) -> list[Finding]:
    """协议异常：路由邻居 Down / 主备切换等单点高危事件。"""
    out = []
    pat = re.compile(r"down|lost|teardown|拆除|失效|inactive", re.I)
    for e in events:
        if e.category == "路由协议" and pat.search(e.msg) and e.sev <= 4:
            m = IP_RE.search(e.raw)
            out.append(Finding(
                kind="协议邻居/会话异常", severity="P1", target=f"{e.host}" + (f" ← {m.group(0)}" if m else ""),
                count=1, first=e.ts, last=e.ts,
                detail=f"{e.module}/{e.code}: {e.msg[:90]}",
                evidence=[e.raw[:120]],
            ))
    return out


def run_all(events: list[Event], params: Optional[dict] = None) -> list[Finding]:
    p = {"window_flap": 5, "min_flap": 4, "window_bf": 10, "min_bf": 5,
         "bucket": 5, "k": 3.0, "min_burst": 8}
    if params:
        p.update(params)
    findings = []
    findings += detect_flapping(events, p["window_flap"], p["min_flap"])
    findings += detect_bruteforce(events, p["window_bf"], p["min_bf"])
    findings += detect_burst(events, p["bucket"], p["k"], p["min_burst"])
    findings += detect_protocol_resets(events)
    findings += detect_offhours(events)
    findings += detect_novelty(events)
    findings.sort(key=lambda f: (SEV_ORDER.get(f.severity, 9), -(f.count or 0)))
    return findings
