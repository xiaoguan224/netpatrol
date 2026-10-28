#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""报告生成层：Markdown / HTML 巡检报告 + 结论建议。

可选增强：设置环境变量 NETPATROL_LLM_API（OpenAI 兼容 /chat/completions 地址）
与 NETPATROL_LLM_KEY 后，会把统计结论交给大模型润色成自然语言段落；
未配置时自动跳过，核心功能零依赖。
"""

from __future__ import annotations

import html
import json
import os
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from .core import Event, __version__ as _v
from .detect import Finding

SEV_COLOR = {"P0": "#c0392b", "P1": "#e67e22", "P2": "#f1c40f", "P3": "#7f8c8d", "P4": "#95a5a6"}


def summarize(events: list[Event], findings: list[Finding]) -> dict:
    sev_c = Counter(e.priority for e in events)
    cat_c = Counter(e.category for e in events)
    host_c = Counter(e.host for e in events)
    ts = [e.ts for e in events if e.ts]
    return {
        "total_events": len(events),
        "time_from": min(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "-",
        "time_to": max(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "-",
        "hosts": len(host_c),
        "by_priority": dict(sev_c),
        "by_category": dict(cat_c),
        "top_hosts": host_c.most_common(5),
        "findings_total": len(findings),
        "findings_by_sev": dict(Counter(f.severity for f in findings)),
        "findings_by_kind": dict(Counter(f.kind for f in findings)),
    }


def build_conclusion(s: dict, findings: list[Finding]) -> list[str]:
    """基于统计结果生成巡检结论（规则式，可被 LLM 润色覆盖）。"""
    lines = []
    if not findings:
        lines.append("本次巡检未发现明显异常，设备运行平稳。")
        return lines
    p0 = [f for f in findings if f.severity == "P0"]
    p1 = [f for f in findings if f.severity == "P1"]
    if p0:
        lines.append(f"发现 {len(p0)} 项 P0 级安全异常，需立即处理：" + "；".join(f"{f.target}（{f.kind}）" for f in p0[:3]) + "。")
    if p1:
        lines.append(f"发现 {len(p1)} 项 P1 级异常，建议今日内核查：" + "；".join(f"{f.target}（{f.kind}）" for f in p1[:4]) + "。")
    kinds = s["findings_by_kind"]
    if kinds.get("接口抖动"):
        lines.append("接口反复 UP/DOWN 会造成路由收敛震荡，建议检查光模块/网线、端口协商与对端设备供电。")
    if kinds.get("疑似暴力破解"):
        lines.append("建议在边界设备启用 login 失败锁定（local-user 认证失败次数限制）并用 ACL 限制管理面访问源。")
    if kinds.get("异常时段操作"):
        lines.append("凌晨出现配置操作，建议核对变更工单与操作人身份，确认是否为计划内变更。")
    if kinds.get("协议邻居/会话异常"):
        lines.append("路由邻居中断会影响业务转发路径，建议核查链路质量与协议保活定时器配置。")
    return lines


def llm_polish(text: str) -> str:
    """可选：调用 OpenAI 兼容接口润色结论。未配置环境变量则原样返回。"""
    api = os.environ.get("NETPATROL_LLM_API")
    key = os.environ.get("NETPATROL_LLM_KEY")
    model = os.environ.get("NETPATROL_LLM_MODEL", "gpt-4o-mini")
    if not api or not key:
        return text
    try:
        body = json.dumps({
            "model": model,
            "messages": [{"role": "user", "content":
                          "你是网络运维工程师，请把以下设备巡检结论改写成简洁专业的中文段落，保留所有事实：\n" + text}],
            "temperature": 0.3,
        }).encode("utf-8")
        req = urllib.request.Request(api.rstrip("/") + "/chat/completions", data=body,
                                     headers={"Content-Type": "application/json",
                                              "Authorization": f"Bearer {key}"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"].strip()
    except Exception as exc:  # 网络/配额失败不影响主流程
        return text + f"\n\n> （LLM 润色跳过：{exc}）"


def to_markdown(events: list[Event], findings: list[Finding], sources: list[str]) -> str:
    s = summarize(events, findings)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    md = [f"# 网络设备日志巡检报告", "",
          f"- 生成时间：{now}　|　工具：netpatrol v{_v}",
          f"- 数据来源：{', '.join(Path(x).name for x in sources)}",
          f"- 日志区间：{s['time_from']} ~ {s['time_to']}（{s['hosts']} 台设备，{s['total_events']} 条事件）", ""]
    md += ["## 一、异常发现（按优先级）", ""]
    if findings:
        md += ["| # | 级别 | 类型 | 对象 | 次数 | 首次 | 说明 |", "|---|------|------|------|------|------|------|"]
        for i, f in enumerate(findings, 1):
            first = f.first.strftime("%m-%d %H:%M") if f.first else "-"
            md.append(f"| {i} | **{f.severity}** | {f.kind} | {f.target} | {f.count} | {first} | {f.detail} |")
        md += ["", "### 证据摘录", ""]
        for i, f in enumerate(findings, 1):
            md.append(f"**{i}. {f.severity} {f.kind} — {f.target}**")
            md.append("```")
            md += [f"  {line}" for line in f.evidence[:4]]
            md.append("```")
            md.append("")
    else:
        md += ["未发现异常。", ""]
    md += ["## 二、事件分布", "",
           "| 优先级 | " + " | ".join(s["by_priority"].keys()) + " |",
           "|---" * (len(s["by_priority"]) + 1) + "|",
           "| 条数 | " + " | ".join(str(v) for v in s["by_priority"].values()) + " |", "",
           "| 类别 | " + " | ".join(s["by_category"].keys()) + " |",
           "|---" * (len(s["by_category"]) + 1) + "|",
           "| 条数 | " + " | ".join(str(v) for v in s["by_category"].values()) + " |", "",
           "## 三、巡检结论与处置建议", ""]
    md += [f"{i}. {line}" for i, line in enumerate(build_conclusion(s, findings), 1)]
    md += ["", "---", "*报告由 netpatrol 自动生成：解析→分类→统计检测→结论。数据均为样例/自有日志，不涉及生产环境。*"]
    return "\n".join(md)


def to_html(md_text: str, events: list[Event], findings: list[Finding]) -> str:
    """轻量 HTML 报告：结论卡片 + 异常表 + 时间轴散点。"""
    s = summarize(events, findings)
    ts = sorted(e.ts for e in events if e.ts)
    timeline = ""
    if ts:
        span = (ts[-1] - ts[0]).total_seconds() or 1
        buckets = defaultdict(lambda: Counter())
        for e in events:
            if e.ts:
                pos = int((e.ts - ts[0]).total_seconds() / span * 59)
                buckets[min(pos, 59)][e.priority] += 1
        bars = []
        for pos in range(60):
            c = buckets.get(pos, Counter())
            h = min(sum(c.values()) * 4, 60)
            color = SEV_COLOR["P0"] if c.get("P0") else SEV_COLOR["P1"] if c.get("P1") else SEV_COLOR["P2"] if c.get("P2") else "#bdc3c7"
            bars.append(f'<div class="bar" style="height:{h}px;background:{color}" title="第{pos*2}%-时间轴: {dict(c)}"></div>')
        timeline = ('<h2>日志时间轴（60 桶，颜色=最高优先级）</h2>'
                    f'<div class="axis">{"".join(bars)}</div>'
                    f'<div class="range">{ts[0]:%m-%d %H:%M} — {ts[-1]:%m-%d %H:%M}</div>')
    rows = "".join(
        f'<tr><td><span class="pill" style="background:{SEV_COLOR[f.severity]}">{f.severity}</span></td>'
        f'<td>{html.escape(f.kind)}</td><td>{html.escape(f.target)}</td><td>{f.count}</td>'
        f'<td>{f.first:%m-%d %H:%M}</td><td>{html.escape(f.detail)}</td></tr>'
        for f in findings) or '<tr><td colspan="6">未发现异常</td></tr>'
    concl = "".join(f"<li>{html.escape(c)}</li>" for c in build_conclusion(s, findings))
    return f"""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<title>netpatrol 巡检报告</title><style>
body{{font-family:"Microsoft YaHei",system-ui,sans-serif;margin:32px auto;max-width:1000px;color:#2c3e50;background:#fafbfc}}
h1{{border-bottom:3px solid #2980b9;padding-bottom:8px}} h2{{margin-top:28px;color:#34495e}}
.meta{{color:#7f8c8d;font-size:14px}} table{{border-collapse:collapse;width:100%;font-size:14px;background:#fff}}
th,td{{border:1px solid #dfe4e8;padding:7px 10px;text-align:left}} th{{background:#eef3f7}}
.pill{{color:#fff;border-radius:10px;padding:1px 9px;font-size:12px}}
.axis{{display:flex;align-items:flex-end;gap:2px;height:64px;background:#fff;border:1px solid #dfe4e8;padding:6px}}
.bar{{flex:1;min-width:2px;border-radius:1px}} .range{{font-size:12px;color:#7f8c8d;margin-top:4px}}
li{{margin:6px 0}} .kpis{{display:flex;gap:14px;flex-wrap:wrap;margin:14px 0}}
.kpi{{background:#fff;border:1px solid #dfe4e8;border-radius:8px;padding:10px 18px;text-align:center}}
.kpi b{{display:block;font-size:22px;color:#2980b9}}</style></head><body>
<h1>网络设备日志巡检报告</h1>
<p class="meta">生成 {datetime.now():%Y-%m-%d %H:%M} ｜ netpatrol ｜ 区间 {s['time_from']} ~ {s['time_to']} ｜ {s['hosts']} 台设备 / {s['total_events']} 条事件</p>
<div class="kpis"><div class="kpi"><b>{s['findings_total']}</b>异常项</div>
<div class="kpi"><b>{s['findings_by_sev'].get('P0',0)}</b>P0 安全</div>
<div class="kpi"><b>{s['findings_by_sev'].get('P1',0)}</b>P1 重要</div>
<div class="kpi"><b>{s['total_events']}</b>日志事件</div></div>
{timeline}
<h2>异常明细</h2><table><tr><th>级别</th><th>类型</th><th>对象</th><th>次数</th><th>首次</th><th>说明</th></tr>{rows}</table>
<h2>巡检结论与处置建议</h2><ul>{concl}</ul>
<p class="meta">报告由 netpatrol 自动生成（解析→分类→统计检测→结论），数据均为样例/自有日志。</p>
</body></html>"""
