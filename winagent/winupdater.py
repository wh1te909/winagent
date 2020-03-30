import subprocess
import json
import requests
import os
from time import sleep
import datetime as dt

from agent import WindowsAgent


class WinUpdater(WindowsAgent):
    def __init__(self):
        super().__init__()
        self.updater_url = f"{self.astor.server}/winupdate/winupdater/"
        self.results_url = f"{self.astor.server}/winupdate/results/"
        self.scan_url = f"{self.astor.server}/api/v1/triggerpatchscan/"
        self.check_payload = {"agent_id": self.astor.agentid}

    def install_update(self, kb):
        r = subprocess.run(
            [
                "c:\\salt\\salt-call.bat",
                "win_wua.get",
                f"{kb}",
                "download=True",
                "install=True",
                "--local",
            ],
            capture_output=True,
        )

        return r.stdout.decode("utf-8", errors="ignore")

    def run(self):
        while 1:
            try:
                resp = requests.get(
                    self.updater_url,
                    data=json.dumps(self.check_payload),
                    headers=self.headers,
                    timeout=15,
                )
            except Exception:
                pass
            else:
                if resp.json() == "nopatches":
                    pass
                else:
                    try:
                        policy = resp.json()[0]["patch_policy"]
                        weekday = dt.datetime.today().weekday()  # Monday 0, Sunday 6
                        hour = dt.datetime.now().hour

                        if (
                            weekday in policy["run_time_days"]
                            and hour == policy["run_time_hour"]
                        ):

                            for patch in resp.json():
                                kb = patch["kb"]
                                install = self.install_update(kb)
                                self.logger.info(install)
                                res_payload = {"agent_id": self.astor.agentid, "kb": kb}
                                status = json.loads(install)

                                if (
                                    status["local"]["Install"]["Updates"]
                                    == "Nothing to install"
                                ):
                                    res_payload.update({"results": "alreadyinstalled"})
                                else:
                                    if status["local"]["Install"]["Success"]:
                                        res_payload.update({"results": "success"})
                                    else:
                                        res_payload.update({"results": "failed"})

                                requests.patch(
                                    self.results_url,
                                    json.dumps(res_payload),
                                    headers=self.headers,
                                    timeout=15,
                                )

                            # trigger a patch scan once all updates finish installing, and check if reboot needed
                            done_payload = {
                                "agent_id": self.astor.agentid,
                                "reboot": self.salt_call_ret_bool(
                                    "win_wua.get_needs_reboot"
                                ),
                            }
                            requests.patch(
                                self.scan_url,
                                data=json.dumps(done_payload),
                                headers=self.headers,
                                timeout=15,
                            )

                    except Exception as e:
                        self.logger.error(e)
            sleep(180)
