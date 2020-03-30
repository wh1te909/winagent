import json
import requests
from time import sleep
from random import randrange

from agent import WindowsAgent, run_asyncio_commands


class CheckRunner(WindowsAgent):
    def __init__(self):
        super().__init__()
        self.checkrunner_url = f"{self.astor.server}/checks/checkrunner/"

    def run(self):
        payload = {"agent_id": self.astor.agentid}
        while 1:
            try:
                resp = requests.get(
                    self.checkrunner_url,
                    data=json.dumps(payload),
                    headers=self.headers,
                    timeout=15,
                )
            except Exception:
                sleep(90)
            else:
                try:
                    data = resp.json()
                    pingchecks = data["pingchecks"]
                    scriptchecks = data["scriptchecks"]
                    interval = int(data["check_interval"])
                    tasks = []

                    if pingchecks:
                        pings = []
                        for check in pingchecks:
                            pings.append(
                                {"cmd": ["ping", f"{check['ip']}"], "id": check["id"],}
                            )

                        for ping in pings:
                            tasks.append(self.ping_check(ping))

                    if scriptchecks:
                        scripts = []
                        for check in scriptchecks:

                            script_path = check["script"]["filepath"]
                            shell = check["script"]["shell"]
                            timeout = check["timeout"]
                            script_filename = check["script"]["filename"]

                            if shell == "python":
                                scripts.append(
                                    {
                                        "cmd": [
                                            "c:\\salt\\salt-call.bat",
                                            "win_agent.run_python_script",
                                            script_filename,
                                            f"timeout={timeout}",
                                        ],
                                        "id": check["id"],
                                    }
                                )
                            else:
                                scripts.append(
                                    {
                                        "cmd": [
                                            "c:\\salt\\salt-call.bat",
                                            "cmd.script",
                                            script_path,
                                            f"shell={shell}",
                                            f"timeout={timeout}",
                                        ],
                                        "id": check["id"],
                                    }
                                )

                        for script in scripts:
                            tasks.append(self.script_check(script))

                    if tasks:
                        results = run_asyncio_commands(tasks, max_concurrent_tasks=20)
                    else:
                        interval = randrange(start=45, stop=90)

                except Exception:
                    pass
                finally:
                    try:
                        sleep(interval)
                    except Exception:
                        sleep(randrange(start=60, stop=120))
