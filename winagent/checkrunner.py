import json
import requests
from time import sleep
from random import randrange
import concurrent.futures

from agent import WindowsAgent


class CheckRunner(WindowsAgent):
    def __init__(self):
        super().__init__()
        self.checkrunner_url = f"{self.astor.server}/checks/checkrunner/"

    def get_checks(self):
        try:
            payload = {"agent_id": self.astor.agentid}
            resp = requests.get(
                self.checkrunner_url,
                data=json.dumps(payload),
                headers=self.headers,
                timeout=15,
            )
        except:
            return False
        else:
            return resp.json()

    def run_checks(self, data):
        diskchecks = data["diskchecks"]
        cpuloadchecks = data["cpuloadchecks"]
        memchecks = data["memchecks"]
        winservicechecks = data["winservicechecks"]
        pingchecks = data["pingchecks"]
        scriptchecks = data["scriptchecks"]
        tasks = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:

            if diskchecks:
                checks = [i for i in diskchecks]
                for check in checks:
                    tasks.append(executor.submit(self.disk_check, check))

            if memchecks:
                checks = [i for i in memchecks]
                for check in checks:
                    tasks.append(executor.submit(self.mem_check, check))

            if winservicechecks:
                checks = [i for i in winservicechecks]
                for check in checks:
                    tasks.append(executor.submit(self.win_service_check, check))

            if cpuloadchecks:
                checks = [i for i in cpuloadchecks]
                for check in checks:
                    tasks.append(executor.submit(self.cpu_load_check, check))

            if pingchecks:
                checks = [i for i in pingchecks]
                for check in checks:
                    tasks.append(executor.submit(self.ping_check, check))

            if scriptchecks:
                checks = [i for i in scriptchecks]
                for check in checks:
                    tasks.append(executor.submit(self.script_check, check))

    def run_once(self):
        ret = self.get_checks()
        if not ret:
            return False
        else:
            try:
                self.run_checks(ret)
            except:
                return False

    def run_forever(self):
        while 1:
            ret = self.get_checks()
            if not ret:
                sleep(90)
            else:
                try:
                    self.run_checks(ret)
                except:
                    pass
                finally:
                    try:
                        sleep(int(ret["check_interval"]))
                    except:
                        sleep(randrange(start=60, stop=120))
