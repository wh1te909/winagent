import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname( __file__ ), '..')))

from winagent import winutils

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