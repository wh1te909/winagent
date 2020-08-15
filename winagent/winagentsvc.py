import json
from random import randrange
from time import sleep

import requests

from agent import WindowsAgent


class WinAgentSvc(WindowsAgent):
    def __init__(self, log_level, log_to):
        super().__init__(log_level, log_to)
        self.update_url = f"{self.astor.server}/api/v1/update/"
        self.hello_url = f"{self.astor.server}/api/v1/hello/"

    def run(self):
        self.logger.info("Agent service started.")
        # wait a bit before starting otherwise boot_time will be inaccurate
        sleep(randrange(start=10, stop=20))
        try:
            info = {
                "agent_id": self.astor.agentid,
                "hostname": self.hostname,
                "operating_system": self.get_os(),
                "total_ram": self.get_total_ram(),
                "plat": self.platform,
                "plat_release": self.get_platform_release(),
                "version": self.version,
                "antivirus": self.get_av(),
                "boot_time": self.get_boot_time(),
            }

            salt_ver = self.get_salt_version()
            if isinstance(salt_ver, str):
                info["salt_ver"] = salt_ver

            self.logger.debug(info)

            r = requests.patch(
                self.update_url, json.dumps(info), headers=self.headers, timeout=30
            )
        except Exception as e:
            self.logger.debug(e)

        sleep(5)

        while 1:
            try:
                payload = {
                    "agent_id": self.astor.agentid,
                    "local_ip": self.get_cmd_output(["ipconfig", "/all"]),
                    "services": self.get_services(),
                    "public_ip": self.get_public_ip(),
                    "used_ram": self.get_used_ram(),
                    "disks": self.get_disks(),
                    "logged_in_username": self.get_logged_on_user(),
                    "boot_time": self.get_boot_time(),
                    "version": self.version,
                }
                self.logger.debug(payload)

                r = requests.patch(
                    self.hello_url,
                    json.dumps(payload),
                    headers=self.headers,
                    timeout=30,
                )

                if isinstance(r.json(), dict) and "recovery" in r.json().keys():
                    if r.json()["recovery"] == "salt":
                        self.spawn_detached_process([self.exe, "-m", "recoversalt"])
                    elif r.json()["recovery"] == "mesh":
                        self.spawn_detached_process([self.exe, "-m", "recovermesh"])
                    elif r.json()["recovery"] == "command":
                        cmd = r.json()["cmd"]
                        self.spawn_detached_process(cmd, shell=True)

            except Exception as e:
                self.logger.debug(e)
            finally:
                sleep(randrange(start=30, stop=120))
