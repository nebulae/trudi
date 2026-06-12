"""Tests for core.device_inventory — the structured setupapi.dev.log parser.

The fixture reproduces the structural trap that defeats a naive search: the device
IDENTITY sits on the `[Device Install]` HEADER line, one line BEFORE the
`Section start` timestamp. A forward-anchored `grep -A "Section start"` skips the
header and never sees the name. The parser pairs header -> next section-start, so
every device falls out as a visible row. Detection rests on that completeness; the
one structural flag (a device exposing both HID and mass-storage interfaces) is a
hint on top of it.
"""
import textwrap

import pytest

from core.device_inventory import parse_device_install_log


# Header line carries the device name; Section start (the timestamp) is the NEXT
# line. Includes: a benign single-interface device, a composite HID+mass-storage
# device (the keystroke-injector structural profile), and a driver-PACKAGE install
# on a .inf path (must be excluded).
_FIXTURE = textwrap.dedent(r"""
    [Device Install Log]
         OS Version = 10.0.10586
    [BeginLog]
    [Boot Session: 2020/01/01 06:57:22.499]
    >>>  [Device Install (Hardware initiated) - USB\VID_AAAA&PID_0001\benign-phone]
    >>>  Section start 2020/02/10 09:00:00.000
         dvi: benign device
    <<<  Section end 2020/02/10 09:00:01.000
    >>>  [Device Install (Hardware initiated) - HID\VID_BEEF&PID_1234&MI_00\kbd-iface]
    >>>  Section start 2020/02/11 10:00:00.000
         dvi: keyboard interface
    <<<  Section end 2020/02/11 10:00:01.000
    >>>  [Device Install (Hardware initiated) - USBSTOR\Disk&VID_BEEF&PID_1234\store-iface]
    >>>  Section start 2020/02/11 10:00:05.000
         dvi: mass-storage interface
    <<<  Section end 2020/02/11 10:00:06.000
    >>>  [Device Install (DiInstallDriver) - C:\WINDOWS\System32\DriverStore\foo.inf]
    >>>  Section start 2020/02/11 10:00:07.000
    <<<  Section end 2020/02/11 10:00:07.500
    """).strip()


@pytest.fixture()
def log_path(tmp_path):
    p = tmp_path / "setupapi.dev.log"
    p.write_text(_FIXTURE, encoding="utf-8")
    return str(p)


class TestParser:
    def test_every_device_enumerated(self, log_path):
        inv = parse_device_install_log(log_path)
        assert inv["success"]
        # The benign device + the composite device. The .inf driver package is NOT
        # a device and must be excluded. Completeness is the point: nothing dropped.
        assert inv["device_count"] == 2

    def test_identity_on_header_line_is_captured(self, log_path):
        # The device name is on the [Device Install] line BEFORE Section start — the
        # anchor a forward-grep skips. The parser must still capture it with the
        # timestamp from the following line.
        inv = parse_device_install_log(log_path)
        phone = [d for d in inv["devices"] if d["vid"] == "aaaa"]
        assert len(phone) == 1
        assert phone[0]["first_seen"] == "2020-02-10 09:00:00"

    def test_composite_hid_storage_flagged(self, log_path):
        # One physical device exposing BOTH keyboard (HID) and mass storage — the
        # vendor-agnostic keystroke-injector profile.
        inv = parse_device_install_log(log_path)
        flagged = inv["flagged"]
        assert len(flagged) == 1
        assert flagged[0]["vid"] == "beef"
        assert any("composite HID + mass-storage" in r
                   for r in flagged[0]["flag_reasons"])

    def test_single_interface_device_not_flagged(self, log_path):
        inv = parse_device_install_log(log_path)
        assert all(d["vid"] != "aaaa" for d in inv["flagged"])

    def test_driver_package_inf_excluded(self, log_path):
        inv = parse_device_install_log(log_path)
        assert not any(d["device_class"].startswith("C:") for d in inv["devices"])
        assert not any("foo.inf" in (d.get("product") or "") for d in inv["devices"])

    def test_coverage_window(self, log_path):
        inv = parse_device_install_log(log_path)
        cw = inv["coverage_window"]
        assert cw["start"][:10] == "2020-02-10"
        assert cw["end"][:10] == "2020-02-11"
        # _spans() (negative_completeness) must see an in-window day covered.
        assert cw["start"][:10] <= "2020-02-11" <= cw["end"][:10]

    def test_missing_file_fails_gracefully(self, tmp_path):
        inv = parse_device_install_log(str(tmp_path / "nope.log"))
        assert inv["success"] is False
