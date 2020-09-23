import json
import os
import re
import shutil
import subprocess
import sys
from time import sleep
from urllib.parse import urlparse

import psutil
import requests
import validators

from agent import AgentStorage, WindowsAgent, db
from mesh import MeshAgent
from utils import disable_sleep_hibernate, enable_ping, enable_rdp


class Installer(WindowsAgent):
    def __init__(
        self,
        api_url,
        client_id,
        site_id,
        agent_desc,
        agent_type,
        power,
        rdp,
        ping,
        auth_token,
        local_salt,
        local_mesh,
        cert,
        log_level,
        log_to="stdout",
    ):
        super().__init__(log_level, log_to)
        self.api_url = api_url
        self.client_id = client_id
        self.site_id = site_id
        self.agent_desc = agent_desc
        self.agent_type = agent_type
        self.disable_power = power
        self.enable_rdp = rdp
        self.enable_ping = ping
        self.auth_token = auth_token
        self.log_level = log_level
        self.log_to = log_to
        self.local_salt = local_salt
        self.local_mesh = local_mesh
        self.cert = cert

    def install(self):
        # check for existing installation and exit if found
        try:
            tac = psutil.win_service_get("tacticalagent")
        except psutil.NoSuchProcess:
            pass
        else:
            self.logger.error(
                """
        Found tacticalagent service. Please uninstall the existing Tactical Agent first before reinstalling.
        If you're trying to perform an upgrade, do so from the RMM web interface.
                """
            )
            sys.stdout.flush()
            sys.exit(1)

        self.agent_id = self.generate_agent_id()
        self.logger.debug(f"{self.agent_id=}")
        sys.stdout.flush()

        # validate the url and get the salt master
        r = urlparse(self.api_url)

        if r.scheme != "https" and r.scheme != "http":
            self.logger.error("api url must contain https or http")
            sys.stdout.flush()
            sys.exit(1)

        if validators.domain(r.netloc):
            self.salt_master = r.netloc
        # will match either ipv4 , or ipv4:port
        elif re.match(r"[0-9]+(?:\.[0-9]+){3}(:[0-9]+)?", r.netloc):
            if validators.ipv4(r.netloc):
                self.salt_master = r.netloc
            else:
                self.salt_master = r.netloc.split(":")[0]
        else:
            self.logger.error("Error parsing api url, unable to get salt-master")
            sys.stdout.flush()
            sys.exit(1)

        self.logger.debug(f"{self.salt_master=}")
        sys.stdout.flush()

        # set the api base url
        self.api = f"{r.scheme}://{r.netloc}"

        token_headers = {
            "content-type": "application/json",
            "Authorization": f"Token {self.auth_token}",
        }

        self.logger.debug(f"{self.api=}")
        self.logger.debug(f"{token_headers=}")

        minion = os.path.join(self.programdir, self.salt_installer)
        self.logger.debug(f"{minion=}")
        sys.stdout.flush()

        if not self.local_salt:
            # download salt
            print("Downloading salt minion", flush=True)
            try:
                r = requests.get(
                    self.salt_minion_exe,
                    stream=True,
                    timeout=900,
                )
            except Exception as e:
                self.logger.error(e)
                sys.stdout.flush()
                sys.exit(1)

            if r.status_code != 200:
                self.logger.error(
                    f"{r.status_code}: Unable to download salt-minion from {self.salt_minion_exe}"
                )
                sys.stdout.flush()
                sys.exit(1)

            with open(minion, "wb") as f:
                for chunk in r.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)

            del r
        else:
            try:
                shutil.copy2(self.local_salt, minion)
            except Exception as e:
                self.logger.error(e)
                sys.stdout.flush()
                sys.exit(1)

        mesh = os.path.join(self.programdir, self.mesh_installer)
        self.logger.debug(f"{mesh=}")
        sys.stdout.flush()

        if not self.local_mesh:
            # download mesh agent
            try:
                r = requests.post(
                    f"{self.api}/api/v2/meshexe/",
                    json.dumps({"arch": self.arch}),
                    headers=token_headers,
                    stream=True,
                    timeout=90,
                    verify=self.cert,
                )
            except Exception as e:
                self.logger.error(e)
                sys.stdout.flush()
                sys.exit(1)

            if r.status_code != 200:
                self.logger.error(r.json())
                sys.stdout.flush()
                sys.exit(1)

            with open(mesh, "wb") as f:
                for chunk in r.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)

            del r

        else:
            try:
                shutil.copy2(
                    self.local_mesh, os.path.join(self.programdir, self.mesh_installer)
                )
            except Exception as e:
                self.logger.error(e)
                sys.stdout.flush()
                sys.exit(1)

        # get the agent's token
        try:
            r = requests.post(
                f"{self.api}/api/v2/newagent/",
                json.dumps({"agent_id": self.agent_id}),
                headers=token_headers,
                timeout=15,
                verify=self.cert,
            )
        except Exception as e:
            self.logger.error(e)
            sys.stdout.flush()
            sys.exit(1)

        if r.status_code != 200:
            self.logger.error(r.json())
            sys.stdout.flush()
            sys.exit(1)

        self.agent_token = r.json()["token"]

        # check for existing mesh installations and remove
        meshAgent = MeshAgent(log_level="INFO", log_to="stdout")

        if meshAgent.mesh_dir:
            meshAgent.remove_mesh(exe=mesh)

        # install mesh
        self.mesh_node_id = meshAgent.install_mesh(exe=mesh)

        self.logger.debug(f"{self.mesh_node_id=}")
        sys.stdout.flush()

        print("Adding agent to dashboard", flush=True)

        payload = {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "client": self.client_id,
            "site": self.site_id,
            "mesh_node_id": self.mesh_node_id,
            "description": self.agent_desc,
            "monitoring_type": self.agent_type,
        }
        self.logger.debug(payload)
        sys.stdout.flush()

        try:
            r = requests.patch(
                f"{self.api}/api/v2/newagent/",
                json.dumps(payload),
                headers=token_headers,
                timeout=60,
                verify=self.cert,
            )
        except Exception as e:
            self.logger.error(e)
            sys.stdout.flush()
            sys.exit(1)

        if r.status_code != 200:
            self.logger.error(r.json())
            sys.stdout.flush()
            sys.exit(1)

        self.agent_pk = r.json()["pk"]
        self.salt_id = r.json()["saltid"]

        try:
            with db:
                db.create_tables([AgentStorage])
                AgentStorage(
                    server=self.api,
                    agentid=self.agent_id,
                    mesh_node_id=self.mesh_node_id,
                    token=self.agent_token,
                    agentpk=self.agent_pk,
                    salt_master=self.salt_master,
                    salt_id=self.salt_id,
                    cert=self.cert if self.cert else None,
                ).save()
        except Exception as e:
            self.logger.error(e)
            sys.stdout.flush()
            sys.exit(1)

        self.load_db()

        # install salt, remove any existing installations first
        try:
            oldsalt = psutil.win_service_get("salt-minion")
        except psutil.NoSuchProcess:
            pass
        else:
            print("Found existing salt-minion. Removing", flush=True)
            self.uninstall_salt()

        print("Installing the salt-minion, this might take a while...", flush=True)

        salt_cmd = [
            self.salt_installer,
            "/S",
            "/custom-config=saltcustom",
            f"/master={self.salt_master}",
            f"/minion-name={self.salt_id}",
            "/start-minion=1",
        ]

        try:
            install_salt = subprocess.run(
                salt_cmd, cwd=self.programdir, shell=True, timeout=300
            )
        except Exception as e:
            self.logger.error(e)
            sys.stdout.flush()
            sys.exit(1)

        attempts = 0
        retries = 20

        while 1:
            try:
                salt_svc = psutil.win_service_get("salt-minion")
            except psutil.NoSuchProcess:
                self.logger.debug("Salt service not installed yet...")
                sys.stdout.flush()
                attempts += 1
                sleep(5)
            else:
                salt_stat = salt_svc.status()
                if salt_stat != "running":
                    self.logger.debug(f"Salt status: {salt_stat}")
                    sys.stdout.flush()
                    attempts += 1
                    sleep(7)
                else:
                    attempts = 0

            if attempts == 0:
                break
            elif attempts >= retries:
                self.logger.error("Unable to install the salt-minion")
                self.logger.error(
                    f"Check the log file in {self.system_drive}\\salt\\var\\log\\salt\\minion"
                )
                sys.stdout.flush()
                sys.exit(1)

        # accept the salt key on the master
        payload = {"saltid": self.salt_id, "agent_id": self.agent_id}
        accept_attempts = 0
        salt_retries = 20

        while 1:
            try:
                r = requests.post(
                    f"{self.api}/api/v2/saltminion/",
                    json.dumps(payload),
                    headers=self.headers,
                    timeout=35,
                    verify=self.cert,
                )
            except Exception as e:
                self.logger.debug(e)
                sys.stdout.flush()
                accept_attempts += 1
                sleep(5)
            else:
                if r.status_code != 200:
                    accept_attempts += 1
                    self.logger.debug(r.json())
                    sys.stdout.flush()
                    sleep(5)
                else:
                    accept_attempts = 0

            if accept_attempts == 0:
                self.logger.debug(r.json())
                sys.stdout.flush()
                break
            elif accept_attempts >= salt_retries:
                self.logger.error("Unable to register salt with the RMM")
                self.logger.error("Installation failed")
                sys.stdout.flush()
                sys.exit(1)

        sleep(10)

        # sync salt modules
        self.logger.debug("Syncing salt modules")
        sys.stdout.flush()

        sync_attempts = 0
        sync_retries = 20

        while 1:
            try:
                r = requests.patch(
                    f"{self.api}/api/v2/saltminion/",
                    json.dumps({"agent_id": self.agent_id}),
                    headers=self.headers,
                    timeout=30,
                    verify=self.cert,
                )
            except Exception as e:
                self.logger.debug(e)
                sys.stdout.flush()
                sync_attempts += 1
                sleep(5)
            else:
                if r.status_code != 200:
                    sync_attempts += 1
                    self.logger.debug(r.json())
                    sys.stdout.flush()
                    sleep(5)
                else:
                    sync_attempts = 0

            if sync_attempts == 0:
                self.logger.debug(r.json())
                sys.stdout.flush()
                break
            elif sync_attempts >= sync_retries:
                self.logger.error("Unable to sync salt modules")
                self.logger.error("Installation failed")
                sys.stdout.flush()
                sys.exit(1)

        sleep(10)  # wait a bit for modules to fully sync

        self.send_system_info()

        # create the scheduled tasks
        try:
            self.create_fix_salt_task()
            self.create_fix_mesh_task()
        except Exception as e:
            self.logger.debug(e)
            sys.stdout.flush()

        # remove services if they exists
        try:
            tac = psutil.win_service_get("tacticalagent")
        except psutil.NoSuchProcess:
            pass
        else:
            print("Found tacticalagent service. Removing...", flush=True)
            subprocess.run([self.nssm, "stop", "tacticalagent"], capture_output=True)
            subprocess.run(
                [self.nssm, "remove", "tacticalagent", "confirm"], capture_output=True
            )

        try:
            chk = psutil.win_service_get("checkrunner")
        except psutil.NoSuchProcess:
            pass
        else:
            print("Found checkrunner service. Removing...", flush=True)
            subprocess.run([self.nssm, "stop", "checkrunner"], capture_output=True)
            subprocess.run(
                [self.nssm, "remove", "checkrunner", "confirm"], capture_output=True
            )

        # install the windows services
        print("Installing services...", flush=True)
        svc_commands = [
            [
                self.nssm,
                "install",
                "tacticalagent",
                self.exe,
                "-m",
                "winagentsvc",
            ],
            [self.nssm, "set", "tacticalagent", "DisplayName", r"Tactical RMM Agent"],
            [self.nssm, "set", "tacticalagent", "Description", r"Tactical RMM Agent"],
            [self.nssm, "start", "tacticalagent"],
            [
                self.nssm,
                "install",
                "checkrunner",
                self.exe,
                "-m",
                "checkrunner",
            ],
            [
                self.nssm,
                "set",
                "checkrunner",
                "DisplayName",
                r"Tactical RMM Check Runner",
            ],
            [
                self.nssm,
                "set",
                "checkrunner",
                "Description",
                r"Tactical RMM Check Runner",
            ],
            [self.nssm, "start", "checkrunner"],
        ]

        for cmd in svc_commands:
            subprocess.run(cmd, capture_output=True)

        if self.disable_power:
            print("Disabling sleep/hibernate...", flush=True)
            try:
                disable_sleep_hibernate()
            except:
                pass

        if self.enable_rdp:
            print("Enabling RDP...", flush=True)
            try:
                enable_rdp()
            except:
                pass

        if self.enable_ping:
            print("Enabling ping...", flush=True)
            try:
                enable_ping()
            except:
                pass

        print("Installation was successfull!", flush=True)
        print(
            "Allow a few minutes for the agent to properly display in the RMM",
            flush=True,
        )
        sys.exit(0)
