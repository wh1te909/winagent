import json
import requests
from time import sleep
from random import randrange

from winutils import ping_check, script_check, run_asyncio_commands
from models import AgentStorage, db


def main():

    with db:
        astor = AgentStorage.select()[0]

    url = f"{astor.server}/checks/checkrunner/"
    headers = {
        "content-type": "application/json",
        "Authorization": f"Token {astor.token}",
    }
    payload = {"agentid": astor.agentid}

    while 1:
        try:
            resp = requests.get(
                url, data=json.dumps(payload), headers=headers, timeout=15
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
                            {
                                "cmd": ["ping", f"{check['ip']}"],
                                "id": check["id"],
                                "token": astor.token,
                                "server": astor.server,
                            }
                        )

                    for ping in pings:
                        tasks.append(ping_check(ping))

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
                                        "run_python.run_python_script",
                                        script_filename,
                                        f"timeout={timeout}",
                                        "--out=json",
                                    ],
                                    "id": check["id"],
                                    "token": astor.token,
                                    "server": astor.server,
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
                                        "--out=json",
                                    ],
                                    "id": check["id"],
                                    "token": astor.token,
                                    "server": astor.server,
                                }
                            )

                    for script in scripts:
                        tasks.append(script_check(script))

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


if __name__ == "__main__":
    main()
