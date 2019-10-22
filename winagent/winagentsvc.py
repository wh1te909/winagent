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
    
    operating_system = winutils.get_os()
    hostname = socket.gethostname()
    total_ram = winutils.get_total_ram()
    cpu_info = winutils.get_cpu_info()
    plat = platform.system().lower()
    plat_release = winutils.get_platform_release()


    while 1:
        try:
            payload = {
                "agentid": astor.agentid,
                "client": astor.client,
                "site": astor.site,
                "mesh_node_id": astor.mesh_node_id,
                "description": astor.description,
                "monitoring_type": astor.agent_type,
                "operating_system": operating_system,
                "hostname": hostname,
                "local_ip": winutils.get_cmd_output("ipconfig /all"),
                "services": winutils.get_services(),
                "public_ip": winutils.get_public_ip(),
                "cpu_load": winutils.get_cpu_load(),
                "total_ram": total_ram,
                "used_ram": winutils.get_used_ram(),
                "disks": winutils.get_disks(),
                "boot_time": winutils.get_boot_time(),
                "logged_in_username": winutils.get_logged_on_user(),
                "cpu_info": cpu_info,
                "platform": plat,
                "platform_release": plat_release,
            }
            
            url = f"{astor.server}/api/v1/hello/"
            headers = {
                "content-type": "application/json",
                "Authorization": f"Token {astor.token}",
            }
            requests.post(url, json.dumps(payload), headers=headers)
        except Exception as e:
            pass
        finally:
            sleep(randrange(start=0, stop=5))


if __name__ == "__main__":
    main()


