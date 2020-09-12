import os
import platform
import sys
from unittest import mock

import pytest
import validators

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..\\winagent"))
)

from agent import WindowsAgent


@pytest.fixture(scope="session", autouse=True)
@mock.patch("agent.WindowsAgent.__init__", return_value=None)
def agent(self):
    return WindowsAgent()


def test_boot_time(agent):
    assert type(agent.get_boot_time()) is float


def test_used_ram(agent):
    assert type(agent.get_used_ram()) is int


def test_total_ram(agent):
    assert type(agent.get_total_ram()) is int


@pytest.mark.skipif("TRAVIS" in os.environ, reason="doesn't work in travis")
def test_services(agent):
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


def test_arch(agent):
    agent.programdir = "C:\\Program Files\\TacticalAgent"

    if platform.machine().lower() == "amd64":
        agent.arch = "64"
        assert (
            agent.salt_minion_exe
            == "https://github.com/wh1te909/winagent/raw/master/bin/salt-minion-setup.exe"
        )
        assert agent.nssm == "C:\\Program Files\\TacticalAgent\\nssm.exe"

    if platform.machine().lower() == "x86":
        agent.arch = "32"
        assert (
            agent.salt_minion_exe
            == "https://github.com/wh1te909/winagent/raw/master/bin/salt-minion-setup-x86.exe"
        )
        assert agent.nssm == "C:\\Program Files\\TacticalAgent\\nssm-x86.exe"
