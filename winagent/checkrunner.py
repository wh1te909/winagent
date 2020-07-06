import asyncio
import json
from time import sleep

import requests

from agent import WindowsAgent


class CheckRunner(WindowsAgent):
    def __init__(self):
        super().__init__()
        self.checkrunner_url = (
            f"{self.astor.server}/api/v1/{self.astor.agentpk}/checkrunner/"
        )

    def get_checks(self):
        try:
            resp = requests.get(self.checkrunner_url, headers=self.headers, timeout=15,)
        except:
            return False
        else:
            try:
                data = resp.json()
                if data["checks"]:
                    return data
                else:
                    return False
            except:
                return False

    async def run_checks(self, data):
        try:
            tasks = []
            checks = data["checks"]

            for check in checks:

                if check["check_type"] == "cpuload":
                    tasks.append(self.cpu_load_check(check))

                elif check["check_type"] == "ping":
                    tasks.append(self.ping_check(check))

                elif check["check_type"] == "script":
                    tasks.append(self.script_check(check))

                elif check["check_type"] == "diskspace":
                    tasks.append(self.disk_check(check))

                elif check["check_type"] == "memory":
                    tasks.append(self.mem_check(check))

                elif check["check_type"] == "winsvc":
                    tasks.append(self.win_service_check(check))

                elif check["check_type"] == "eventlog":
                    tasks.append(self.event_log_check(check))

            await asyncio.gather(*tasks)

        except Exception as e:
            self.logger.error(f"Error running checks: {e}")

    def run(self):
        ret = self.get_checks()
        if not ret:
            return False
        else:
            try:
                asyncio.run(self.run_checks(ret))
            except Exception as e:
                self.logger.error(f"Error running manual checks: {e}")
                return False

    def run_forever(self):
        self.logger.info("Checkrunner service started")

        while 1:
            interval = 120
            try:
                ret = self.get_checks()
            except:
                sleep(interval)
            else:
                if ret:
                    try:
                        interval = int(ret["check_interval"])
                        asyncio.run(self.run_checks(ret))
                    except:
                        pass
                    finally:
                        sleep(interval)
                else:
                    sleep(interval)
