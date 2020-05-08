import json
import requests
from time import sleep
from random import randrange
from concurrent.futures import ThreadPoolExecutor
from threading import BoundedSemaphore

from agent import WindowsAgent


# https://www.bettercodebytes.com/theadpoolexecutor-with-a-bounded-queue-in-python/
class BoundedExecutor:
    def __init__(self, bound, max_workers):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.semaphore = BoundedSemaphore(bound + max_workers)

    def submit(self, fn, *args, **kwargs):
        self.semaphore.acquire()
        try:
            future = self.executor.submit(fn, *args, **kwargs)
        except:
            self.semaphore.release()
            raise
        else:
            future.add_done_callback(lambda x: self.semaphore.release())
            return future

    def shutdown(self, wait=True):
        self.executor.shutdown(wait)


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
        tasks = []

        if diskchecks:
            checks = [_ for _ in diskchecks]
            for check in checks:
                tasks.append((self.disk_check, check))

        if memchecks:
            checks = [_ for _ in memchecks]
            for check in checks:
                tasks.append((self.mem_check, check))

        if winservicechecks:
            checks = [_ for _ in winservicechecks]
            for check in checks:
                tasks.append((self.win_service_check, check))

        if cpuloadchecks:
            checks = [_ for _ in cpuloadchecks]
            for check in checks:
                tasks.append((self.cpu_load_check, check))

        if pingchecks:
            checks = [_ for _ in pingchecks]
            for check in checks:
                tasks.append((self.ping_check, check))

        if scriptchecks:
            checks = [_ for _ in scriptchecks]
            for check in checks:
                tasks.append((self.script_check, check))

        if tasks:
            results = []
            executor = BoundedExecutor(10, 15)

            for task in tasks:
                r = executor.submit(*task)
                results.append(r)
                sleep(0.2)

            return [i.result() for i in results]
        
        else:
            return "notasks"

    def run_once(self):
        self.logger.info("Running checks manually")
        ret = self.get_checks()
        if not ret:
            return False
        else:
            try:
                run = self.run_checks(ret)
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
                    run = self.run_checks(ret)
                except Exception as e:
                    self.logger.error(f"Error running checks: {e}")
                finally:
                    try:
                        sleep(int(ret["check_interval"]))
                    except:
                        sleep(randrange(start=60, stop=120))
