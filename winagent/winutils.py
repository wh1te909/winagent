import wmi
import platform
import requests
import ctypes
import re
from win32com.client import GetObject
import subprocess
import json
import psutil
import os
import math
import validators
import asyncio
import datetime as dt
from collections import defaultdict
from ctypes.wintypes import BYTE, WORD, DWORD, WCHAR

try:
    from subprocess import DEVNULL
except ImportError:
    DEVNULL = os.open(os.devnull, os.O_RDWR)

kernel32 = ctypes.WinDLL(str("kernel32"), use_last_error=True)


def make_chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i : i + n]


async def script_check(cmd):
    output = (
        "Script started " + dt.datetime.now().strftime("%c") + "\n" + "-" * 40 + "\n"
    )
    retcode = 99
    proc = await asyncio.create_subprocess_exec(
        *cmd["cmd"], stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )

    proc_stdout, proc_stderr = await proc.communicate()

    if proc_stdout:
        resp = json.loads(proc_stdout.decode("utf-8", errors="ignore"))
        retcode = resp["local"]["retcode"]
        out = resp["local"]["stdout"]
        err = resp["local"]["stderr"]

        if out:
            output += "STDOUT:\n" + resp["local"]["stdout"]

        if err:
            output += "\nSTDERR:\n" + resp["local"]["stderr"]

    if proc_stderr:
        output += proc_stderr.decode("utf-8", errors="ignore")

    output += (
        "\n"
        + "-" * 40
        + "\nScript finished at "
        + dt.datetime.now().strftime("%c")
        + f"\nreturn code: {retcode}"
    )

    if retcode != 0:
        status = "failing"
    else:
        status = "passing"

    url = f"{cmd['server']}/checks/updatescriptcheck/"
    headers = {
        "content-type": "application/json",
        "Authorization": f"Token {cmd['token']}",
    }
    payload = {"output": output, "status": status, "id": cmd["id"]}
    resp = requests.patch(url, json.dumps(payload), headers=headers)

    return status


async def ping_check(cmd):

    proc = await asyncio.create_subprocess_exec(
        *cmd["cmd"], stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()

    success = ["Reply", "bytes", "time", "TTL"]
    status = ""

    if stdout:
        output = stdout.decode("utf-8", errors="ignore")
        if all(x in output for x in success):
            status = "passing"
        else:
            status = "failing"

    if stderr:
        status = "failing"
        output = "error running ping check"

    url = f"{cmd['server']}/checks/updatepingcheck/"
    headers = {
        "content-type": "application/json",
        "Authorization": f"Token {cmd['token']}",
    }
    payload = {"output": output, "id": cmd["id"], "status": status}
    resp = requests.patch(url, json.dumps(payload), headers=headers)
    return status


# source: https://fredrikaverpil.github.io/2017/06/20/async-and-await-with-subprocesses/
def run_asyncio_commands(tasks, max_concurrent_tasks=0):

    all_results = []

    if max_concurrent_tasks == 0:
        chunks = [tasks]
        num_chunks = len(chunks)
    else:
        chunks = make_chunks(l=tasks, n=max_concurrent_tasks)
        num_chunks = len(list(make_chunks(l=tasks, n=max_concurrent_tasks)))

    if asyncio.get_event_loop().is_closed():
        asyncio.set_event_loop(asyncio.new_event_loop())

    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    loop = asyncio.get_event_loop()

    chunk = 1
    for tasks_in_chunk in chunks:
        commands = asyncio.gather(*tasks_in_chunk)  # Unpack list using *
        results = loop.run_until_complete(commands)
        all_results += results
        chunk += 1

    loop.close()
    return all_results


def get_av():
    r = subprocess.run(
        [
            "wmic",
            "/Namespace:\\\\root\SecurityCenter2",
            "Path",
            "AntiVirusProduct",
            "get",
            "displayName" "/FORMAT:List",
        ],
        capture_output=True,
    )

    if r.stdout:
        out = r.stdout.decode().lower().replace(" ", "").splitlines()
        out[:] = [i for i in out if i != ""]  # remove empty list items

        if len(out) == 1 and out[0] == "displayname=windowsdefender":
            return "windowsdefender"

        elif len(out) == 2:
            if "displayname=windowsdefender" in out:
                out.remove("displayname=windowsdefender")
                return out[0].split("displayname=", 1)[1]

        return "n/a"

    elif r.stderr:
        return "n/a"
    else:
        return "n/a"


def get_boot_time():
    return psutil.boot_time()


def get_cpu_load():
    return psutil.cpu_percent(interval=5)


def get_used_ram():
    return round(psutil.virtual_memory().percent)


def get_services():
    return [svc.as_dict() for svc in psutil.win_service_iter()]


def get_total_ram():
    return math.ceil((psutil.virtual_memory().total / 1_073_741_824))


def get_logged_on_user():
    try:
        return psutil.users()[0].name
    except Exception:
        return "None"


def get_public_ip():

    try:
        ifconfig = requests.get("https://ifconfig.co/ip", timeout=5).text.strip()

        if not validators.ipv4(ifconfig) and not validators.ipv6(ifconfig):
            icanhaz = requests.get("https://icanhazip.com", timeout=7).text.strip()

            if not validators.ipv4(icanhaz) and not validators.ipv6(icanhaz):
                return "error"
            else:
                return icanhaz
        else:
            return ifconfig

    except Exception:
        return "error"


def get_cmd_output(cmd):

    try:
        r = subprocess.run(cmd, capture_output=True)
    except Exception:
        return "error getting output"

    if r.stdout:
        return r.stdout.decode()
    elif r.stderr:
        return r.stderr.decode()
    else:
        return "error getting output"


def get_os():
    try:
        os = wmi.WMI().Win32_OperatingSystem()[0]
        return f"{os.Caption}, {platform.architecture()[0]} (build {os.BuildNumber})"
    except Exception:
        return "unknown-os"

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


def get_disks():
    disks = defaultdict(dict)
    try:
        for part in psutil.disk_partitions(all=False):
            if os.name == "nt":
                if "cdrom" in part.opts or part.fstype == "":
                    continue
            usage = psutil.disk_usage(part.mountpoint)
            device = part.device.split("\\", 1)[0]
            disks[device]["device"] = device
            disks[device]["total"] = bytes2human(usage.total)
            disks[device]["used"] = bytes2human(usage.used)
            disks[device]["free"] = bytes2human(usage.free)
            disks[device]["percent"] = int(usage.percent)
            disks[device]["fstype"] = part.fstype
    except Exception:
        disks = {"error": "error getting disk info"}

    return disks


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


def get_platform_release():
    try:
        os = get_os_version_info()
        grains = get_windows_os_release_grain(os["Caption"], os["ProductType"])
        plat = platform.system().lower()
        plat_release = f"{plat}-{grains}"
    except Exception:
        plat_release = "unknown-release"

    return plat_release


def salt_call_ret_bool(cmd):
    try:
        r = subprocess.run(
            [
                "c:\\salt\\salt-call.bat",
                cmd,
                "--local",
            ],
            capture_output=True,
        )
    except Exception:
        return False
    else:
        ret = json.loads(r.stdout.decode("utf-8", errors="ignore"))
        if ret["local"]:
            return True
        else:
            return False

