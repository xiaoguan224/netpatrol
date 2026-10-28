# -*- coding: utf-8 -*-
"""netpatrol —— 网络设备日志智能巡检工具（零第三方依赖）。"""
from .core import __version__, load_events, parse_line
from .detect import run_all
from .report import to_markdown, to_html

__all__ = ["__version__", "load_events", "parse_line", "run_all", "to_markdown", "to_html"]
