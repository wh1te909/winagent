import sys
import os
import validators
import pytest
import unittest.mock as mock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from winagent.agent import WindowsAgent


@pytest.fixture(scope="session", autouse=True)
@mock.patch("winagent.agent.WindowsAgent.__init__", return_value=None)
def agent(self):
    return WindowsAgent()


def test_os(agent):
    assert "Microsoft Windows" in agent.get_os()


def test_boot_time(agent):
    assert type(agent.get_boot_time()) is float


def test_cpu_load(agent):
    assert type(agent.get_cpu_load()) is float


def test_used_ram(agent):
    assert type(agent.get_used_ram()) is int


def test_total_ram(agent):
    assert type(agent.get_total_ram()) is int


def test_services(agent):
    if "TRAVIS" in os.environ:
        assert 1 == 1
    else:
        services = agent.get_services()
        spooler = list(filter(lambda x: x["name"] == "Spooler", services))[0]
        assert type(services) is list
        assert spooler["display_name"] == "Print Spooler"
        assert spooler["username"] == "LocalSystem"


def test_disks(agent):
    disks = agent.get_disks()
    assert disks["C:"]["device"] == "C:"


def test_os(agent):
    assert "Microsoft Windows" in agent.get_os()


def test_cmd_output(agent):
    output = agent.get_cmd_output(["ping", "8.8.8.8"])
    success = ["Reply", "bytes", "time", "TTL"]
    assert all(x in output for x in success)


def test_public_ip(agent):
    error = []
    if not validators.ipv4(agent.get_public_ip()) and not validators.ipv6(
        agent.get_public_ip()
    ):
        error.append("not ipv4 or ipv6")

    assert not error


def test_platform_release(agent):
    assert "windows" in agent.get_platform_release().lower()
