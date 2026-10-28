# -*- coding: utf-8 -*-
"""CLI 入口：python -m netpatrol <demo|analyze> ..."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import load_events
from .detect import run_all
from .report import to_markdown, to_html, summarize

PKG_DIR = Path(__file__).resolve().parent.parent


def cmd_analyze(args) -> int:
    paths = [Path(p) for p in args.logs]
    for p in paths:
        if not p.exists():
            print(f"[!] 文件不存在: {p}", file=sys.stderr)
            return 2
    events, unparsed = load_events(paths)
    if not events:
        print("[!] 没有解析出任何事件，请检查日志格式", file=sys.stderr)
        return 1
    params = {}
    if args.window:
        params["window_flap"] = args.window
    if args.min_fail:
        params["min_bf"] = args.min_fail
    findings = run_all(events, params)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    md = to_markdown(events, findings, [str(p) for p in paths])
    (out / "report.md").write_text(md, encoding="utf-8")
    (out / "findings.json").write_text(
        json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2), encoding="utf-8")
    if args.html:
        (out / "report.html").write_text(to_html(md, events, findings), encoding="utf-8")
    s = summarize(events, findings)
    print(f"[ok] 解析 {s['total_events']} 条事件（未识别 {len(unparsed)} 行），"
          f"发现异常 {s['findings_total']} 项 "
          f"P0={s['findings_by_sev'].get('P0', 0)} P1={s['findings_by_sev'].get('P1', 0)}")
    for f in findings[:8]:
        print(f"  [{f.severity}] {f.kind:8s} {f.target:28s} x{f.count:<3d} {f.detail[:56]}")
    print(f"[ok] 报告已写入 {out / 'report.md'}" + (f" / {out / 'report.html'}" if args.html else ""))
    if unparsed and args.verbose:
        print("--- 未解析行（前10） ---")
        for line in unparsed[:10]:
            print("  " + line)
    return 0


def cmd_demo(args) -> int:
    sample = PKG_DIR / "samples" / "huawei_router_demo.log"
    ns = argparse.Namespace(logs=[str(sample)], out=args.out, html=True,
                            window=None, min_fail=None, verbose=True)
    print(f"[demo] 使用内置样例日志: {sample}")
    return cmd_analyze(ns)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="netpatrol", description="网络设备日志智能巡检（零依赖）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="分析一个或多个日志文件")
    a.add_argument("logs", nargs="+")
    a.add_argument("-o", "--out", default="reports", help="输出目录（默认 reports/）")
    a.add_argument("--html", action="store_true", help="同时输出 HTML 报告")
    a.add_argument("--json", action="store_true", help="额外输出 JSON（默认已输出 findings.json）")
    a.add_argument("--window", type=int, help="抖动检测窗口（分钟）")
    a.add_argument("--min-fail", type=int, dest="min_fail", help="爆破判定阈值（次）")
    a.add_argument("-v", "--verbose", action="store_true")
    a.set_defaults(func=cmd_analyze)
    d = sub.add_parser("demo", help="用内置样例日志演示完整流程")
    d.add_argument("-o", "--out", default="reports")
    d.set_defaults(func=cmd_demo)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
