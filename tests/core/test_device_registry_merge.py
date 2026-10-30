"""SYSTEM-hive USB history merged into the setupapi device inventory."""
import os

from core.device_inventory import (merge_registry_devices, parse_device_install_logs,
                                   parse_registry_usb)

# RegRipper usb + usbstor output as seen on the Bogus Bill laptop (+ one USBSTOR key).
_RR = """usb v.20200515
ControlSet001\\Enum\\USB

VID_03F0&PID_042A [2024-04-01 09:45:25Z]
  S/N: 000000000QH80YASPR1a [2024-04-01 09:45:25Z]

VID_03F0&PID_042A&MI_00 [2024-04-01 09:45:25Z]
  S/N: 7&e1ef228&0&0000 [2024-04-01 09:45:25Z]

VID_03F0&PID_042A&MI_02 [2024-04-01 09:45:26Z]

VID_0E0F&PID_0003 [2022-04-01 00:50:26Z]

usbstor v.20200515
Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00 [2023-02-03 10:00:00Z]
  S/N: 4C530001 [2023-02-03 10:00:00Z]
"""

_SETUPAPI = """>>>  [Device Install (Hardware initiated) - USB\\VID_0E0F&PID_0003\\6&1]
>>>  Section start 2022/04/01 00:50:26.123
"""


def test_parse_registry_usb_groups_interfaces():
    devs = {d["identity"]: d for d in parse_registry_usb(_RR)}
    hp = devs["vidpid:03f0:042a"]
    assert hp["interfaces"] == ["00", "02"]
    assert hp["registry_last_write"] == "2024-04-01 09:45:26Z"
    assert devs["venprod:sandisk:cruzer_blade"]["device_class"] == "USBSTOR"


def test_merge_marks_registry_only_devices(tmp_path):
    log = tmp_path / "setupapi.dev.log"
    log.write_text(_SETUPAPI)
    inv = merge_registry_devices(parse_device_install_logs([str(log)]), parse_registry_usb(_RR))
    only = sorted(d["identity"] for d in inv["registry_only"])
    assert only == ["venprod:sandisk:cruzer_blade", "vidpid:03f0:042a"]
    both = next(d for d in inv["devices"] if d["identity"] == "vidpid:0e0f:0003")
    assert both["sources"] == ["registry", "setupapi"]
    assert inv["device_count"] == 3


def test_archived_logs_and_hive_discovery(tmp_path):
    from tools.misc import _archived_setupapi_logs, _system_hive_beside
    win = tmp_path / "Windows"
    (win / "INF").mkdir(parents=True)
    (win / "System32" / "config").mkdir(parents=True)
    (win / "System32" / "config" / "SYSTEM").write_bytes(b"regf")
    live = win / "INF" / "setupapi.dev.log"
    live.write_text(_SETUPAPI)
    (win / "INF" / "setupapi.dev.20230101_101010.log").write_text(_SETUPAPI)
    (win / "INF" / "setupapi.setup.log").write_text("x")
    assert [os.path.basename(p) for p in _archived_setupapi_logs(str(live))] == \
        ["setupapi.dev.20230101_101010.log"]
    assert _system_hive_beside(str(live)) == str(win / "System32" / "config" / "SYSTEM")
