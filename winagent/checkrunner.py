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
            try:
                return resp.json()
            except:
                return False

    def run_checks(self, data):

        diskchecks = data["diskchecks"]
        cpuloadchecks = data["cpuloadchecks"]
        memchecks = data["memchecks"]
        winservicechecks = data["winservicechecks"]
        pingchecks = data["pingchecks"]
        scriptchecks = data["scriptchecks"]

        with concurrent.futures.ProcessPoolExecutor() as executor:

            if diskchecks:
                checks = [_ for _ in diskchecks]
                for check in checks:
                    executor.submit(self.disk_check, check)
                sleep(0.1)

            if memchecks:
                checks = [_ for _ in memchecks]
                for check in checks:
                    executor.submit(self.mem_check, check)
                sleep(0.1)

            if winservicechecks:
                checks = [_ for _ in winservicechecks]
                for check in checks:
                    executor.submit(self.win_service_check, check)
                sleep(0.1)

            if cpuloadchecks:
                checks = [_ for _ in cpuloadchecks]
                for check in checks:
                    executor.submit(self.cpu_load_check, check)
                sleep(0.1)

            if pingchecks:
                checks = [_ for _ in pingchecks]
                for check in checks:
                    executor.submit(self.ping_check, check)
                sleep(0.1)

            if scriptchecks:
                checks = [_ for _ in scriptchecks]
                for check in checks:
                    executor.submit(self.script_check, check)
                    sleep(0.3)

    def run_once(self):
        self.logger.info("Running checks manually")
        ret = self.get_checks()
        if not ret:
            return False
        else:
            try:
                self.run_checks(ret)
            except Exception as e:
                self.logger.error(f"Error running checks: {e}")
                return False

    def run_forever(self):
        self.logger.info("Checkrunner service started")
        while 1:
            ret = self.get_checks()
            if not ret:
                sleep(90)
            else:
                try:
                    self.run_checks(ret)
                except Exception as e:
                    self.logger.error(f"Error running checks: {e}")
                finally:
                    try:
                        sleep(int(ret["check_interval"]))
                    except:
                        sleep(randrange(start=60, stop=120))
