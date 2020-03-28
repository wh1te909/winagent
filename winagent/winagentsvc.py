import json
import requests
from time import sleep
from random import randrange

from agent import WindowsAgent


class WinAgentSvc(WindowsAgent):
    def __init__(self):
        super().__init__()
        self.update_url = f"{self.astor.server}/api/v1/update/"
        self.hello_url = f"{self.astor.server}/api/v1/hello/"

    def run(self):
        self.logger.info("Agent started.")
        info = {
            "agentid": self.astor.agentid,
            "hostname": self.hostname,
            "operating_system": self.get_os(),
            "total_ram": self.get_total_ram(),
            "platform": self.platform,
            "platform_release": self.get_platform_release(),
            "version": self.astor.version,
            "av": self.get_av(),
            "boot_time": self.get_boot_time(),
        }
        try:
            requests.patch(self.update_url, json.dumps(info), headers=self.headers)
        except Exception:
            pass

        while 1:
            try:
                payload = {
                    "agentid": self.astor.agentid,
                    "local_ip": self.get_cmd_output(["ipconfig", "/all"]),
                    "services": self.get_services(),
                    "public_ip": self.get_public_ip(),
                    "cpu_load": self.get_cpu_load(),
                    "used_ram": self.get_used_ram(),
                    "disks": self.get_disks(),
                    "logged_in_username": self.get_logged_on_user(),
                }

                requests.patch(
                    self.hello_url, json.dumps(payload), headers=self.headers
                )
            except Exception:
                pass
            finally:
                sleep(randrange(start=15, stop=30))
