import json
import requests
from time import sleep
import asyncio

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
                data = resp.json()
                if data["checks"]["total"] > 0:
                    return data
                else:
                    return False
            except:
                return False

    async def run_checks(self, data):
        try:
            diskchecks = data["diskchecks"]
            cpuloadchecks = data["cpuloadchecks"]
            memchecks = data["memchecks"]
            winservicechecks = data["winservicechecks"]
            pingchecks = data["pingchecks"]
            scriptchecks = data["scriptchecks"]
            tasks = []

            if cpuloadchecks:
                checks = [_ for _ in cpuloadchecks]
                for check in checks:
                    tasks.append(self.cpu_load_check(check))

            if pingchecks:
                checks = [_ for _ in pingchecks]
                for check in checks:
                    tasks.append(self.ping_check(check))

            if scriptchecks:
                checks = [_ for _ in scriptchecks]
                for check in checks:
                    tasks.append(self.script_check(check))

            if diskchecks:
                checks = [_ for _ in diskchecks]
                for check in checks:
                    tasks.append(self.disk_check(check))

            if memchecks:
                checks = [_ for _ in memchecks]
                for check in checks:
                    tasks.append(self.mem_check(check))

            if winservicechecks:
                checks = [_ for _ in winservicechecks]
                for check in checks:
                    tasks.append(self.win_service_check(check))

            if tasks:
                await asyncio.gather(*tasks)

        except Exception as e:
            self.logger.error(f"Error running checks: {e}")

    def run(self):
        ret = self.get_checks()
        if not ret:
            return False
        else:
            try:
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
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
                        asyncio.set_event_loop_policy(
                            asyncio.WindowsProactorEventLoopPolicy()
                        )
                        asyncio.run(self.run_checks(ret))
                    except:
                        pass
                    finally:
                        sleep(interval)
                else:
                    sleep(interval)
