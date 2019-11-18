import socket
import platform
import json
import requests
from time import sleep
from random import randrange

from models import AgentStorage, db
import winutils


def main():

    with db:
        astor = AgentStorage.select()[0]
    
    headers = {
        "content-type": "application/json",
        "Authorization": f"Token {astor.token}"
    }

    info = {
        "agentid": astor.agentid,
        "hostname": socket.gethostname(),
        "operating_system": winutils.get_os(),
        "total_ram": winutils.get_total_ram(),
        "cpu_info": winutils.get_cpu_info(),
        "platform": platform.system().lower(),
        "platform_release": winutils.get_platform_release(),
        "version": astor.version,
        "av": winutils.get_av()
    }

    try:
        update_url = f"{astor.server}/api/v1/update/"
        requests.patch(update_url, json.dumps(info), headers=headers)
    except Exception:
        pass


    while 1:
        try:
            payload = {
                "agentid": astor.agentid,
                "local_ip": winutils.get_cmd_output("ipconfig /all"),
                "services": winutils.get_services(),
                "public_ip": winutils.get_public_ip(),
                "cpu_load": winutils.get_cpu_load(),
                "used_ram": winutils.get_used_ram(),
                "disks": winutils.get_disks(),
                "boot_time": winutils.get_boot_time(),
                "logged_in_username": winutils.get_logged_on_user()
            }
            
            hello_url = f"{astor.server}/api/v1/hello/"
            requests.patch(hello_url, json.dumps(payload), headers=headers)
        except Exception as e:
            pass
        finally:
            sleep(randrange(start=0, stop=5))


if __name__ == "__main__":
    main()


