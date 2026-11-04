# -*- coding: utf-8 -*-
"""netpatrol 单元测试：python -m unittest discover tests -v"""
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netpatrol.core import parse_line, make_template, classify, load_events, Event
from netpatrol.detect import (detect_flapping, detect_bruteforce, detect_protocol_resets,
                              detect_offhours, detect_novelty, detect_burst, run_all)
from netpatrol.report import to_markdown, to_html, summarize

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "huawei_router_demo.log"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "vrp_formats.log"


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

    def test_novelty_template(self):
        rare = ev(datetime(2026, 7, 11, 16, 40, 0), "R1", "POWER", 3, "POWER_FAIL",
                  "Power supply 2 in slot 0 failed, redundancy lost")
        repeat = [ev(datetime(2026, 7, 11, 8, i, 0), "R1", "DEV", 4, "CPU_USAGE",
                     f"CPU usage is {40 + i}%, threshold is 80%") for i in range(3)]
        found = detect_novelty([rare] + repeat)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].kind, "罕见错误模板")
        self.assertIn("<N>", found[0].detail)


class TestRealVrpFormats(unittest.TestCase):
    """行式取自华为官方《信息的输出格式》与 eNSP 终端回显，不是真机导出。"""

    def test_event_lines_parse(self):
        events, unparsed, skipped = load_events([FIXTURE])
        self.assertEqual(unparsed, [])
        by_line = {e.line_no: e for e in events}
        self.assertEqual(by_line[1].ts, datetime(2026, 9, 2, 10, 11, 12))   # +08:00 被剥掉
        self.assertEqual(by_line[2].sev, 4)                                 # '#' Trap 行
        self.assertEqual(by_line[3].ts, datetime(2026, 7, 10, 8, 24, 2))    # 毫秒 + 斜杠日期
        self.assertEqual(by_line[4].code, "NBR_CHG")                        # (d)[5] 序号
        self.assertEqual(by_line[5].ts.year, 2026)                          # short-date 补年份
        self.assertEqual(by_line[6].module, "SYS")                          # <PRI> 前缀
        self.assertEqual(by_line[7].host, "R1")                              # [R1] 前缀
        self.assertEqual(by_line[7].category, "认证安全")
        self.assertEqual(by_line[8].category, "VPN隧道")
        self.assertTrue(all("(l)" not in e.msg and "[0]" not in e.msg for e in events))

    def test_terminal_noise_is_skipped_not_unparsed(self):
        events, unparsed, skipped = load_events([FIXTURE])
        self.assertEqual(unparsed, [])
        self.assertEqual(len(events), 9)
        self.assertEqual(len(skipped), 15)
        self.assertTrue(any("More" in s for s in skipped))
        self.assertTrue(any("Versatile" in s for s in skipped))
        self.assertTrue(any("Logging buffer" in s for s in skipped))
        self.assertTrue(any("Current messages" in s for s in skipped))

    def test_terminal_wrap_is_rejoined(self):
        """eNSP 会在第 80 列硬折一行，续行没有时间戳（真机日志里 6 条有 6 个折行）。"""
        events, unparsed, skipped = load_events([FIXTURE])
        self.assertEqual(unparsed, [])
        merged = [s for s in skipped if "折行" in s]
        self.assertEqual(len(merged), 1)
        phy = [e for e in events if e.module == "PHY"]
        self.assertEqual(len(phy), 1)
        self.assertEqual(phy[0].msg, "GigabitEthernet0/0/1: change status to up")
        self.assertEqual(phy[0].category, "接口链路")


class TestBurstBaseline(unittest.TestCase):
    """频率突增的基线口径：空桶要计入、待判定的桶不能算进自己的基线。

    这两条都是真机日志逼出来的。R3/R4 那份 237 行日志分成 16/16/44 三个桶，
    旧实现把 44 自己算进均值和 σ，阈值被抬到 64.9，最大的突发反而漏报。
    """

    @staticmethod
    def _bucket(n, minute, module="IFNET", code="LINK_STATE"):
        t0 = datetime(2026, 11, 3, 18, 0, 0)
        base = t0 + timedelta(minutes=minute)
        return [ev(base + timedelta(seconds=i), "R3", module, 4, code,
                   f"burst probe {i} on GigabitEthernet0/0/1") for i in range(n)]

    def test_burst_not_masked_by_its_own_spike(self):
        events = self._bucket(16, 0) + self._bucket(16, 5) + self._bucket(44, 20)
        out = detect_burst(events)
        self.assertEqual(len(out), 1, "44 条的桶必须报出来，不能因自身抬高阈值而漏报")
        self.assertEqual(out[0].count, 44)
        self.assertIn("其余 4 个时间桶", out[0].detail)

    def test_empty_buckets_count_toward_baseline(self):
        # 只有 2 个桶有日志（1 条 / 9 条），跨度 6 个桶：中间的空档也要算进基线
        events = self._bucket(1, 0) + self._bucket(9, 25)
        out = detect_burst(events)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].count, 9)
        self.assertIn("含空桶", out[0].detail)

    def test_steady_traffic_is_not_burst(self):
        events = []
        for m in range(0, 30, 5):
            events += self._bucket(10, m)
        self.assertEqual(detect_burst(events), [], "完全平稳的 10 条/桶不该报突增")

    def test_burst_boundary_is_one_above_threshold(self):
        flat = self._bucket(10, 0) + self._bucket(10, 5) + self._bucket(10, 10) + self._bucket(10, 15)
        self.assertEqual(detect_burst(flat + self._bucket(10, 20)), [])       # 刚好等于基线 → 不报
        self.assertEqual(len(detect_burst(flat + self._bucket(11, 20))), 1)   # 多一条 → 报

    def test_too_few_events_returns_empty(self):
        self.assertEqual(detect_burst(self._bucket(4, 0) + self._bucket(4, 1)), [])


class TestEndToEnd(unittest.TestCase):
    def test_sample_log_finds_all_planted_scenarios(self):
        events, unparsed, _skipped = load_events([SAMPLE])
        self.assertEqual(unparsed, [])
        self.assertGreater(len(events), 150)
        findings = run_all(events)
        kinds = {f.kind for f in findings}
        for expected in ["接口抖动", "疑似暴力破解", "协议邻居/会话异常", "异常时段操作",
                         "日志频率突增", "罕见错误模板"]:
            self.assertIn(expected, kinds, f"未检出埋点场景: {expected}")

    def test_report_generation(self):
        events, _, _ = load_events([SAMPLE])
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
