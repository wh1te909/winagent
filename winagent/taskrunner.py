import json
import requests
import subprocess
from time import perf_counter

from agent import WindowsAgent


class TaskRunner(WindowsAgent):
    def __init__(self, task_pk):
        super().__init__()
        self.task_pk = task_pk
        self.task_url = f"{self.astor.server}/automation/taskrunner/{self.task_pk}/"

    def run(self):
        ret = self.get_task()
        if not ret:
            return False
        else:
            self.run_task(ret)

    def get_task(self):
        try:
            resp = requests.get(self.task_url, headers=self.headers, timeout=15,)
        except:
            return False
        else:
            return resp.json()

    def run_task(self, data):

        try:
            script = data["script"]
            timeout = data["timeout"]
        except Exception as e:
            self.logger.error(e)
            return False

        try:
            if script["shell"] == "python":
                cmd = [
                    self.salt_call,
                    "win_agent.run_python_script",
                    script["filename"],
                    f"timeout={timeout}",
                ]
            else:
                cmd = [
                    self.salt_call,
                    "cmd.script",
                    script["filepath"],
                    f"shell={script['shell']}",
                    f"timeout={timeout}",
                ]

            start = perf_counter()
            r = subprocess.run(cmd, capture_output=True)
            stop = perf_counter()

            if r.stdout:
                resp = json.loads(r.stdout.decode("utf-8", errors="ignore"))
                retcode = resp["local"]["retcode"]
                stdout = resp["local"]["stdout"]
                stderr = resp["local"]["stderr"]

            elif r.stderr:
                retcode = 99
                stdout = ""
                stderr = r.stderr.decode("utf-8", errors="ignore")

            payload = {
                "stdout": stdout,
                "stderr": stderr,
                "retcode": retcode,
                "execution_time": "{:.4f}".format(round(stop - start)),
            }

            resp = requests.patch(
                self.task_url, json.dumps(payload), headers=self.headers, timeout=15,
            )

        except Exception as e:
            self.logger.error(e)

        return "ok"
