import json
import requests
from time import sleep
from random import randrange

from winutils import ping_check, run_asyncio_commands
from models import AgentStorage, db

def main():

    with db:
        astor = AgentStorage.select()[0]
    
    url = f"{astor.server}/checks/checkrunner/"
    headers = {
        "content-type": "application/json",
        "Authorization": f"Token {astor.token}"
    }
    payload = {"agentid": astor.agentid}

    while 1:
        try:
            resp = requests.get(url, data=json.dumps(payload), headers=headers, timeout=15)
        except Exception:
            sleep(90)
        else:
            try:
                data = resp.json()
                pingchecks = data["pingchecks"]
                interval = int(data["ping_check_interval"])
                tasks = []

                if pingchecks:
                    pings = []
                    for check in pingchecks:
                        pings.append(
                            {
                                "cmd": ["ping", f"{check['ip']}"],
                                "id": check['id'],
                                "token": astor.token,
                                "server": astor.server
                            }
                        )
                
                    for ping in pings:
                        tasks.append(ping_check(ping))
             
                if tasks:
                    results = run_asyncio_commands(
                        tasks, max_concurrent_tasks=20
                    )
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