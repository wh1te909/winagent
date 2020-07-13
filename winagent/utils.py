import ctypes
import re
import signal
from ctypes.wintypes import BYTE, DWORD, WCHAR, WORD

import psutil
import wmi

kernel32 = ctypes.WinDLL(str("kernel32"), use_last_error=True)


def kill_proc(pid):
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        children.append(parent)
        for p in children:
            p.send_signal(signal.SIGTERM)

        gone, alive = psutil.wait_procs(children, timeout=20, callback=None)
    except:
        pass


def bytes2human(n):
    # http://code.activestate.com/recipes/578019
    symbols = ("K", "M", "G", "T", "P", "E", "Z", "Y")
    prefix = {}
    for i, s in enumerate(symbols):
        prefix[s] = 1 << (i + 1) * 10
    for s in reversed(symbols):
        if n >= prefix[s]:
            value = float(n) / prefix[s]
            return "%.1f%s" % (value, s)
    return "%sB" % n


# source: https://github.com/saltstack/salt/blob/master/salt/grains/core.py
def os_version_info_ex():
    class OSVersionInfo(ctypes.Structure):
        _fields_ = (
            ("dwOSVersionInfoSize", DWORD),
            ("dwMajorVersion", DWORD),
            ("dwMinorVersion", DWORD),
            ("dwBuildNumber", DWORD),
            ("dwPlatformId", DWORD),
            ("szCSDVersion", WCHAR * 128),
        )

        def __init__(self, *args, **kwds):
            super(OSVersionInfo, self).__init__(*args, **kwds)
            self.dwOSVersionInfoSize = ctypes.sizeof(self)
            kernel32.GetVersionExW(ctypes.byref(self))

    class OSVersionInfoEx(OSVersionInfo):
        _fields_ = (
            ("wServicePackMajor", WORD),
            ("wServicePackMinor", WORD),
            ("wSuiteMask", WORD),
            ("wProductType", BYTE),
            ("wReserved", BYTE),
        )

    return OSVersionInfoEx()


def get_os_version_info():
    info = os_version_info_ex()
    c = wmi.WMI()
    c_info = c.Win32_OperatingSystem()[0]

    ret = {
        "MajorVersion": info.dwMajorVersion,
        "MinorVersion": info.dwMinorVersion,
        "BuildNumber": info.dwBuildNumber,
        "PlatformID": info.dwPlatformId,
        "ServicePackMajor": info.wServicePackMajor,
        "ServicePackMinor": info.wServicePackMinor,
        "SuiteMask": info.wSuiteMask,
        "ProductType": info.wProductType,
        "Caption": c_info.Caption,
        "Arch": c_info.OSArchitecture,
        "Version": c_info.Version,
    }
    return ret


# source: https://github.com/saltstack/salt/blob/master/salt/grains/core.py
def get_windows_os_release_grain(caption, product_type):

    version = "Unknown"
    release = ""
    if "Server" in caption:
        for item in caption.split(" "):

            if re.match(r"\d+", item):
                version = item

            if re.match(r"^R\d+$", item):
                release = item
        os_release = f"{version}Server{release}"
    else:
        for item in caption.split(" "):
            if re.match(r"^(\d+(\.\d+)?)|Thin|Vista|XP$", item):
                version = item
        os_release = version

    if os_release in ["Unknown"]:
        os_release = platform.release()
        server = {
            "Vista": "2008Server",
            "7": "2008ServerR2",
            "8": "2012Server",
            "8.1": "2012ServerR2",
            "10": "2016Server",
        }

        # (Product Type 1 is Desktop, Everything else is Server)
        if product_type > 1 and os_release in server:
            os_release = server[os_release]

    return os_release
