# -*- coding: utf-8 -*-
"""netpatrol 单元测试：python -m unittest discover tests -v"""
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netpatrol.core import parse_line, make_template, classify, load_events, Event
from netpatrol.detect import detect_flapping, detect_bruteforce, detect_protocol_resets, detect_offhours, run_all
from netpatrol.report import to_markdown, to_html, summarize

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "huawei_router_demo.log"


def ev(ts, host, module, sev, code, msg):
    e = Event(ts=ts, host=host, module=module, sev=sev, code=code, msg=msg, raw=msg)
    e.template = make_template(msg)
    classify(e)
    return e


class TestParser(unittest.TestCase):
    def test_huawei_ts_year_middle(self):
        line = "Jul 10 2026 14:02:00.100 R1 %%10IFNET/4/LINK_STATE(d): GigabitEthernet0/0/3 physical state is DOWN"
        e = parse_line(line, 1, 2026)
        self.assertIsNotNone(e)
        self.assertEqual(e.ts, datetime(2026, 7, 10, 14, 2, 0))
        self.assertEqual(e.host, "R1")
        self.assertEqual(e.module, "IFNET")
        self.assertEqual(e.sev, 4)
        self.assertEqual(e.code, "LINK_STATE")

    def test_huawei_ts_year_tail(self):
        line = "Jul 10 08:23:45 2026 R2 %%10SSH2/4/SFTP_AUTH_FAIL: Source user admin attempts to login through SSH failed, source ip is 192.0.2.66"
        e = parse_line(line, 1, 2026)
        self.assertIsNotNone(e)
        self.assertEqual(e.ts, datetime(2026, 7, 10, 8, 23, 45))
        self.assertEqual(e.category, "认证安全")

    def test_garbage_returns_none(self):
        self.assertIsNone(parse_line("这不是日志", 1, 2026))

    def test_template_normalization(self):
        t = make_template("Neighbor 10.0.0.5 interface GigabitEthernet0/0/1 Down after 120 seconds")
        self.assertIn("<IP>", t)
        self.assertIn("<IFACE>", t)
        self.assertIn("<N>", t)


class TestDetectors(unittest.TestCase):
    def test_flapping(self):
        base = datetime(2026, 7, 10, 14, 0, 0)
        evs = [ev(base + timedelta(seconds=i * 30), "R1", "IFNET", 4, "LINK_STATE",
                  f"GigabitEthernet0/0/3 physical state is {'DOWN' if i % 2 else 'UP'}") for i in range(6)]
        found = detect_flapping(evs, window_min=5, min_transitions=4)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].kind, "接口抖动")
        self.assertIn("GIGABITETHERNET0/0/3", found[0].target.upper())

    def test_no_flap_when_stable_up(self):
        base = datetime(2026, 7, 10, 14, 0, 0)
        evs = [ev(base.replace(minute=i), "R1", "IFNET", 4, "LINK_STATE",
                  "GigabitEthernet0/0/3 physical state is UP") for i in range(6)]
        self.assertEqual(detect_flapping(evs), [])

    def test_bruteforce(self):
        base = datetime(2026, 7, 10, 21, 0, 0)
        evs = [ev(base + timedelta(seconds=i * 10), "R1", "SSH2", 4, "SFTP_AUTH_FAIL",
                  f"Source user u{i} attempts to login through SSH failed, source ip is 192.0.2.66") for i in range(6)]
        found = detect_bruteforce(evs, window_min=10, min_fail=5)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "P0")
        self.assertIn("192.0.2.66", found[0].target)

    def test_ospf_down(self):
        e = ev(datetime(2026, 7, 11, 2, 15, 0), "R1", "OSPF", 3, "OSPF_NBR_DOWN",
               "Neighbor 10.0.0.5 interface GigabitEthernet0/0/1 Down: InactivityTimer expired")
        found = detect_protocol_resets([e])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "P1")

    def test_offhours_config(self):
        e = ev(datetime(2026, 7, 11, 1, 23, 0), "R1", "SHELL", 5, "CMDRECORD",
               "Command is system-view; [R1] acl number 3999")
        found = detect_offhours([e])
        self.assertEqual(len(found), 1)


class TestEndToEnd(unittest.TestCase):
    def test_sample_log_finds_all_planted_scenarios(self):
        events, unparsed = load_events([SAMPLE])
        self.assertEqual(unparsed, [])
        self.assertGreater(len(events), 150)
        findings = run_all(events)
        kinds = {f.kind for f in findings}
        for expected in ["接口抖动", "疑似暴力破解", "协议邻居/会话异常", "异常时段操作", "日志频率突增"]:
            self.assertIn(expected, kinds, f"未检出埋点场景: {expected}")

    def test_report_generation(self):
        events, _ = load_events([SAMPLE])
        findings = run_all(events)
        md = to_markdown(events, findings, ["demo.log"])
        self.assertIn("巡检报告", md)
        self.assertIn("疑似暴力破解", md)
        s = summarize(events, findings)
        self.assertEqual(s["total_events"], len(events))
        h = to_html(md, events, findings)
        self.assertIn("<!DOCTYPE html>", h)
        self.assertIn("P0", h)


if __name__ == "__main__":
    unittest.main(verbosity=2)
