import json
import subprocess

import requests

from agent import WindowsAgent


class WinUpdater(WindowsAgent):
    def __init__(self, log_level, log_to):
        super().__init__(log_level, log_to)
        self.updater_url = f"{self.astor.server}/winupdate/winupdater/"
        self.results_url = f"{self.astor.server}/winupdate/results/"
        self.scan_url = f"{self.astor.server}/api/v1/triggerpatchscan/"
        self.check_payload = {"agent_id": self.astor.agentid}

    def install_update(self, kb):
        try:
            r = subprocess.run(
                [
                    self.salt_call,
                    "win_wua.get",
                    f"{kb}",
                    "download=True",
                    "install=True",
                    "--local",
                ],
                capture_output=True,
                timeout=7200,
            )
            ret = r.stdout.decode("utf-8", errors="ignore")
            self.logger.debug(ret)
            return ret
        except Exception as e:
            self.logger.debug(e)

    def trigger_patch_scan(self):
        try:
            payload = {
                "agent_id": self.astor.agentid,
                "reboot": self.salt_call_ret_bool("win_wua.get_needs_reboot"),
            }
            r = requests.patch(
                self.scan_url,
                data=json.dumps(payload),
                headers=self.headers,
                timeout=60,
            )
        except Exception as e:
            self.logger.debug(e)
            return False

        return "ok"

    def install_all(self):
        try:
            resp = requests.get(
                self.updater_url,
                data=json.dumps(self.check_payload),
                headers=self.headers,
                timeout=30,
            )
        except Exception as e:
            self.logger.debug(e)
            return False
        else:
            if resp.json() == "nopatches":
                return False
            else:
                try:
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
                            timeout=30,
                        )

                    # trigger a patch scan once all updates finish installing, and check if reboot needed
                    self.trigger_patch_scan()

                except Exception as e:
                    self.logger.debug(e)
