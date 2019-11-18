import json
import requests
import asyncio
from time import sleep

from models import AgentStorage, db


def make_chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i : i + n]


async def ping_check(cmd):

    proc = await asyncio.create_subprocess_exec(
        *cmd['cmd'],
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()

    success = ["Reply", "bytes", "time", "TTL"]
    status = ""

    if stdout:
        output = stdout.decode("utf-8", errors="ignore")
        if all(x in output for x in success):
            status = "passing"
        else:
            status = "failing"
    
    if stderr:
        status = "failing"
        output = "error running ping check"
    
    url = f"{cmd['server']}/checks/updatepingcheck/"
    headers = {
        "content-type": "application/json",
        "Authorization": f"Token {cmd['token']}",
    }
    payload = {
        "output": output,
        "id": cmd['id'],
        "status": status
    }
    resp = requests.patch(url, json.dumps(payload), headers=headers)


# source: https://fredrikaverpil.github.io/2017/06/20/async-and-await-with-subprocesses/
def run_asyncio_commands(tasks, max_concurrent_tasks=0):

    all_results = []

    if max_concurrent_tasks == 0:
        chunks = [tasks]
        num_chunks = len(chunks)
    else:
        chunks = make_chunks(l=tasks, n=max_concurrent_tasks)
        num_chunks = len(list(make_chunks(l=tasks, n=max_concurrent_tasks)))

    if asyncio.get_event_loop().is_closed():
        asyncio.set_event_loop(asyncio.new_event_loop())

    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    loop = asyncio.get_event_loop()

    chunk = 1
    for tasks_in_chunk in chunks:
        commands = asyncio.gather(*tasks_in_chunk)  # Unpack list using *
        results = loop.run_until_complete(commands)
        all_results += results
        chunk += 1

    loop.close()
    return all_results


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
            sleep(15)
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
                    interval = 10

            except Exception:
                pass
            finally:
                try:
                    sleep(interval)
                except Exception:
                    sleep(30)


if __name__ == "__main__":
    main()