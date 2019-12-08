import subprocess
import json
import requests
import os
import logging
from time import sleep

from models import AgentStorage, db
from winutils import get_needs_reboot

logging.basicConfig(
    filename="update.log",
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)


def install_update(kb):

    if os.path.exists("c:\\salt\\salt-call.bat"):
        r = subprocess.run(
        [
            "c:\\salt\\salt-call.bat", 
            "win_wua.get",
            f"{kb}", 
            "download=True",
            "install=True",
            "--local", 
            "--out=json"
        ], capture_output=True)
    else:
        try:
            r = subprocess.run(
            [
                "salt-call", 
                "win_wua.get", 
                f"{kb}", 
                "download=True",
                "install=True", 
                "--local", 
                "--out=json"
            ], shell=True, capture_output=True)

        except Exception:
            return "error"
            
    if r.stderr:
        return "error"
    
    return r.stdout.decode("utf-8", errors="ignore")


if __name__ == "__main__":

    with db:
        astor = AgentStorage.select()[0]
        
    updater_url = f"{astor.server}/winupdate/winupdater/"
    results_url = f"{astor.server}/winupdate/results/"
    scan_url = f"{astor.server}/api/v1/triggerpatchscan/"
    headers = {
        "content-type": "application/json",
        "Authorization": f"Token {astor.token}"
    }
    check_payload = {"agentid": astor.agentid}

    while 1:
        try:
            resp = requests.get(updater_url, data=json.dumps(check_payload), headers=headers, timeout=15)
        except Exception:
            pass
        else:
            if resp.json() == "nopatches":
                pass
            else:
                try:
                    for patch in resp.json():
                        kb = patch["kb"]
                        install = install_update(kb)
                        logging.info(install)
                        res_payload = {"agentid": astor.agentid, "kb": kb}

                        if install == "error":
                            res_payload.update({"results": "error"})
                        else:
                            status = json.loads(install)
                            if status["local"]["Install"]["Updates"] == "Nothing to install":
                                res_payload.update({"results": "alreadyinstalled"})
                            else:
                                if status["local"]["Install"]["Success"]:
                                    res_payload.update({"results": "success"})
                                else:
                                    res_payload.update({"results": "failed"})
                        
                        requests.patch(results_url, json.dumps(res_payload), headers=headers, timeout=15)

                    # trigger a patch scan once all updates finish installing, and check if reboot needed 
                    done_payload = { "agentid": astor.agentid, "reboot": get_needs_reboot() }  
                    requests.patch(scan_url, data=json.dumps(done_payload), headers=headers, timeout=15)
                except Exception as e:
                    logging.error(e)
        sleep(30)
