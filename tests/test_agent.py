import sys
import os
import validators

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from winagent import winutils


def test_checkrunner():
    pings = []
    tasks = []
    ips = [
        "8.8.8.8",
        "google.com",
        "1.1.1.1",
        "ak4j287asdjashdk45345kjad",
        "facebook.com",
        "0.0.0.0",
    ]

    for ip in ips:
        pings.append(
            {
                "cmd": ["ping", ip],
                "id": 3,
                "token": "abc",
                "server": "https://google.com",
            }
        )

    for ping in pings:
        tasks.append(winutils.ping_check(ping))

    results = winutils.run_asyncio_commands(tasks, max_concurrent_tasks=20)

    assert results == ["passing", "passing", "passing", "failing", "passing", "failing"]


def test_boot_time():
    assert type(winutils.get_boot_time()) is float


def test_cpu_load():
    assert type(winutils.get_cpu_load()) is float


def test_used_ram():
    assert type(winutils.get_used_ram()) is int


def test_total_ram():
    assert type(winutils.get_total_ram()) is int


def test_cpu_info():
    assert type(winutils.get_cpu_info()) is list


def test_services():
    services = winutils.get_services()
    spooler = list(filter(lambda x: x["name"] == "Spooler", services))[0]
    assert type(services) is list
    assert spooler["display_name"] == "Print Spooler"
    assert spooler["username"] == "LocalSystem"


def test_disks():
    disks = winutils.get_disks()
    assert disks["C:"]["device"] == "C:"


def test_cpu_info():
    assert type(winutils.get_cpu_info()[0]["physical_cores"]) is int


def test_os():
    assert "Microsoft Windows" in winutils.get_os()


def test_cmd_output():
    output = winutils.get_cmd_output(["ping", "8.8.8.8"])
    success = ["Reply", "bytes", "time", "TTL"]
    assert all(x in output for x in success)


def test_public_ip():
    error = []
    if not validators.ipv4(winutils.get_public_ip()) and not validators.ipv6(
        winutils.get_public_ip()
    ):
        error.append("not ipv4 or ipv6")

    assert not error


def test_platform_release():
    assert "windows" in winutils.get_platform_release().lower()
