# -*- coding: utf-8 -*-
"""生成演示用样例日志（全部为脚本合成的模拟数据，不含任何真实网络信息）。

埋入 5 类可被 netpatrol 检出的场景：接口抖动 / SSH 爆破 / OSPF 邻居 Down /
凌晨异常配置操作 / 日志频率突增，外加两天跨度的正常噪声。
"""
import random
from datetime import datetime, timedelta

random.seed(42)
D1 = datetime(2026, 7, 10, 0, 0, 0)
lines = []


def log(dt, host, module, sev, code, msg, ctx=""):
    c = f"({ctx})" if ctx else ""
    lines.append((dt, f"{dt:%b %d %Y} {dt:%H:%M:%S}.{dt.microsecond // 1000:03d} {host} "
                      f"%%10{module}/{sev}/{code}{c}: {msg}"))


# ---- 正常噪声：两天内随机分布 ----
normal = [
    ("SYS", 5, "SYSTEM_STARTUP", "The system is up and running"),
    ("STP", 5, "PORT_FORWARDING", "GigabitEthernet0/0/{n} changes state to forwarding"),
    ("OSPF", 5, "OSPF_NBR_CHANGE", "Neighbor 10.0.{n}.1 state changes to Full"),
    ("SSH2", 5, "SFTP_LOGIN_OK", "Source user admin{u} attempts to login through SSH succeed, source ip is 10.1.0.{n}"),
    ("DEV", 5, "CPU_USAGE", "CPU usage is {p}%, threshold is 80%"),
    ("IFNET", 5, "LINK_STATE", "GigabitEthernet0/0/{n} physical state is UP"),
]
for i in range(120):
    dt = D1 + timedelta(minutes=random.randint(0, 2880), seconds=random.randint(0, 59))
    m, sev, code, msg = random.choice(normal)
    log(dt, random.choice(["R1", "R2", "SW1"]), m, sev, code,
        msg.format(n=random.randint(1, 24), u=random.randint(1, 9), p=random.randint(5, 40)))

# ---- 场景1：接口抖动 R1 GE0/0/3 五连翻 ----
t = D1 + timedelta(hours=14, minutes=2)
for i, st in enumerate(["DOWN", "UP", "DOWN", "UP", "DOWN", "UP"]):
    log(t + timedelta(seconds=i * 38), "R1", "IFNET", 4, "LINK_STATE",
        f"GigabitEthernet0/0/3 physical state is {st}", "d")

# ---- 场景2：SSH 爆破 192.0.2.66 两分钟 9 次失败 ----
t = D1 + timedelta(hours=21)
for i, u in enumerate(["admin", "root", "huawei", "test", "oracle", "ubuntu", "ops", "netadmin", "dcadmin"]):
    log(t + timedelta(seconds=i * 14), "R1", "SSH2", 4, "SFTP_AUTH_FAIL",
        f"Source user {u} attempts to login through SSH failed, source ip is 192.0.2.66")

# ---- 场景3：OSPF 邻居 Down（凌晨2点15） ----
t = D1 + timedelta(days=1, hours=2, minutes=15)
log(t, "R1", "OSPF", 3, "OSPF_NBR_DOWN", "Neighbor 10.0.0.5 interface GigabitEthernet0/0/1 Down: InactivityTimer expired", "d")
log(t + timedelta(seconds=90), "R1", "OSPF", 4, "OSPF_NBR_CHANGE", "Neighbor 10.0.0.5 state changes from Full to Down")

# ---- 场景4：凌晨 01:23 异常配置操作 ----
t = D1 + timedelta(days=1, hours=1, minutes=23)
log(t, "R1", "SHELL", 5, "CMDRECORD", "Command is system-view; [R1] acl number 3999", "")
log(t + timedelta(seconds=25), "R1", "SHELL", 5, "CMDRECORD", "Command is rule deny ip source 192.0.2.0 0.0.0.255; [R1] quit")

# ---- 场景5：频率突增 第2天10:00-10:04 SW1 集中刷 STP 拓扑变更 ----
t = D1 + timedelta(days=1, hours=10)
for i in range(22):
    log(t + timedelta(seconds=i * 10), "SW1", "STP", 4, "TOPOLOGY_CHANGE",
        f"Topology version changed to {100 + i}, root port GigabitEthernet0/0/{i % 8 + 1} changed")

lines.sort(key=lambda x: x[0])
out = "\n".join(s for _, s in lines) + "\n"
with open("samples/huawei_router_demo.log", "w", encoding="utf-8") as f:
    f.write(out)
print(f"生成 {len(lines)} 行样例日志 -> samples/huawei_router_demo.log")
