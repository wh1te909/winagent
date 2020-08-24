import json
import logging
import os
import random
import re
import shutil
import socket
import string
import subprocess
import sys
from time import sleep
from urllib.parse import urlparse

import psutil
import requests
import validators

from agent import AgentStorage, db
from utils import kill_proc, disable_sleep_hibernate, enable_ping, enable_rdp


class Installer:
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
        log_level="INFO",
    ):
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
        self.local_salt = local_salt
        self.local_mesh = local_mesh
        self.programdir = "C:\\Program Files\\TacticalAgent"
        self.headers = {
            "content-type": "application/json",
            "Authorization": f"Token {self.auth_token}",
        }
        self.agent_hostname = socket.gethostname()
        self.nssm = os.path.join(self.programdir, "nssm.exe")
        self.tacticalrmm = os.path.join(self.programdir, "tacticalrmm.exe")
        self.mesh_success = True
        self.accept_success = True
        self.sync_success = True
        logging.basicConfig(
            level=logging.getLevelName(self.log_level),
            format="%(asctime)s - %(module)s - %(funcName)s - %(lineno)d - %(levelname)s - %(message)s",
            handlers=[logging.StreamHandler(sys.stdout)],
        )
        self.logger = logging.getLogger(__name__)

    def rand_string(self):
        chars = string.ascii_letters
        return "".join(random.choice(chars) for i in range(35))

    def uninstall_salt(self):
        print("Stopping salt-minion service", flush=True)
        r = subprocess.run(
            ["sc", "stop", "salt-minion"], timeout=45, capture_output=True
        )
        sleep(15)

        # clean up any hung salt python procs
        pids = []
        for proc in psutil.process_iter():
            with proc.oneshot():
                if proc.name() == "python.exe" and "salt" in proc.exe():
                    pids.append(proc.pid)

        for pid in pids:
            self.logger.debug(f"Killing salt process with pid {pid}")
            try:
                kill_proc(pid)
            except:
                continue

        print("Uninstalling existing salt-minion", flush=True)
        r = subprocess.run(
            ["c:\\salt\\uninst.exe", "/S"], timeout=120, capture_output=True
        )
        sleep(20)

        try:
            shutil.rmtree("C:\\salt")
            sleep(1)
            os.system('rmdir /S /Q "{}"'.format("C:\\salt"))
        except Exception:
            pass

        print("Salt was removed", flush=True)

    def install(self):
        # check for existing installation and exit if found
        try:
            tac = psutil.win_service_get("tacticalagent")
        except psutil.NoSuchProcess:
            pass
        else:
            print(
                "Found tacticalagent service. Please uninstall the existing Tactical Agent first before reinstalling.",
                flush=True,
            )
            print(
                "If you're trying to perform an upgrade, do so from the RMM web interface.",
                flush=True,
            )
            sys.exit(1)

        # generate the agent id
        try:
            r = subprocess.run(
                ["wmic", "csproduct", "get", "uuid"], capture_output=True
            )
            wmic_id = r.stdout.decode("utf-8", errors="ignore").splitlines()[2].strip()
        except Exception:
            self.agent_id = f"{self.rand_string()}|{self.agent_hostname}"
        else:
            self.agent_id = f"{wmic_id}|{self.agent_hostname}"

        self.logger.debug(f"Agent ID: {self.agent_id}")
        sys.stdout.flush()
        # validate the url and get the salt master
        r = urlparse(self.api_url)

        if r.scheme != "https" and r.scheme != "http":
            print("ERROR: api url must contain https or http", flush=True)
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
            print("Error parsing api url, unable to get salt-master", flush=True)
            sys.exit(1)

        self.logger.debug(f"Salt master is: {self.salt_master}")
        sys.stdout.flush()

        # set the api base url
        self.api = f"{r.scheme}://{r.netloc}"

        # get the agent's token
        url = f"{self.api}/api/v1/token/"
        payload = {"agent_id": self.agent_id}
        try:
            r = requests.post(
                url, json.dumps(payload), headers=self.headers, timeout=15
            )
        except Exception as e:
            self.logger.error(e)
            sys.stdout.flush()
            print(
                "ERROR: Unable to contact the RMM. Please check your internet connection.",
                flush=True,
            )
            sys.exit(1)

        if r.status_code == 401:
            print(
                "ERROR: Token has expired. Please generate a new one from the rmm.",
                flush=True,
            )
            sys.exit(1)
        elif r.status_code != 200:
            e = json.loads(r.text)["error"]
            self.logger.error(e)
            sys.stdout.flush()
            sys.exit(1)
        else:
            self.agent_token = json.loads(r.text)["token"]

        if not self.local_salt:
            # download salt
            print("Downloading salt minion", flush=True)
            try:
                r = requests.get(
                    "https://github.com/wh1te909/winagent/raw/master/bin/salt-minion-setup.exe",
                    stream=True,
                    timeout=900,
                )
            except Exception as e:
                self.logger.error(e)
                sys.stdout.flush()
                print("ERROR: Timed out trying to download the salt-minion", flush=True)
                sys.exit(1)

            if r.status_code != 200:
                print(
                    "ERROR: Something went wrong while downloading the salt-minion",
                    flush=True,
                )
                sys.exit(1)

            minion = os.path.join(self.programdir, "salt-minion-setup.exe")
            with open(minion, "wb") as f:
                for chunk in r.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)

            del r
        else:
            try:
                shutil.copy2(
                    self.local_salt,
                    os.path.join(self.programdir, "salt-minion-setup.exe"),
                )
            except Exception as e:
                print(e, flush=True)
                print(
                    f"\nERROR: unable to copy the file {self.local_salt} to {self.programdir}",
                    flush=True,
                )
                sys.exit(1)
            else:
                minion = os.path.join(self.programdir, "salt-minion-setup.exe")

        if not self.local_mesh:
            # download mesh agent
            url = f"{self.api}/api/v1/getmeshexe/"
            try:
                r = requests.post(url, headers=self.headers, stream=True, timeout=400)
            except Exception as e:
                self.logger.error(e)
                sys.stdout.flush()
                print("ERROR: Timed out trying to download the Mesh Agent", flush=True)
                sys.exit(1)

            if r.status_code != 200:
                print(
                    "ERROR: Something went wrong while downloading the Mesh Agent",
                    flush=True,
                )
                sys.exit(1)

            mesh = os.path.join(self.programdir, "meshagent.exe")
            with open(mesh, "wb") as f:
                for chunk in r.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)

            del r

        else:
            try:
                shutil.copy2(
                    self.local_mesh, os.path.join(self.programdir, "meshagent.exe")
                )
            except Exception as e:
                print(e, flush=True)
                print(
                    f"\nERROR: unable to copy the file {self.local_mesh} to {self.programdir}",
                    flush=True,
                )
                sys.exit(1)
            else:
                mesh = os.path.join(self.programdir, "meshagent.exe")

        # check for existing mesh installations and remove
        mesh_exists = False
        mesh_one_dir = "C:\\Program Files\\Mesh Agent"
        mesh_two_dir = "C:\\Program Files\\mesh\\Mesh Agent"

        if os.path.exists(mesh_one_dir):
            mesh_exists = True
            mesh_cleanup_dir = mesh_one_dir
        elif os.path.exists(mesh_two_dir):
            mesh_exists = True
            mesh_cleanup_dir = mesh_two_dir

        if mesh_exists:
            print("Found existing Mesh Agent. Removing...", flush=True)
            try:
                subprocess.run(
                    ["sc", "stop", "mesh agent"], capture_output=True, timeout=30
                )
                sleep(5)
            except:
                pass

            mesh_pids = []
            mesh_procs = [
                p.info
                for p in psutil.process_iter(attrs=["pid", "name"])
                if "meshagent" in p.info["name"].lower()
            ]

            if mesh_procs:
                for proc in mesh_procs:
                    mesh_pids.append(proc["pid"])

            if mesh_pids:
                for pid in mesh_pids:
                    kill_proc(pid)

            try:
                r = subprocess.run(
                    [mesh, "-fulluninstall"], capture_output=True, timeout=60
                )
            except:
                print("Timed out trying to uninstall existing Mesh Agent", flush=True)

            if os.path.exists(mesh_cleanup_dir):
                try:
                    shutil.rmtree(mesh_cleanup_dir)
                    sleep(1)
                    os.system('rmdir /S /Q "{}"'.format(mesh_cleanup_dir))
                except:
                    pass

        # install the mesh agent
        print("Installing mesh agent", flush=True)
        try:
            ret = subprocess.run(
                [mesh, "-fullinstall"], capture_output=True, timeout=120
            )
        except:
            print("Timed out trying to install the Mesh Agent", flush=True)
        sleep(15)

        # meshcentral changed their installation path recently
        mesh_one = os.path.join(mesh_one_dir, "MeshAgent.exe")
        mesh_two = os.path.join(mesh_two_dir, "MeshAgent.exe")

        if os.path.exists(mesh_one):
            mesh_exe = mesh_one
        elif os.path.exists(mesh_two):
            mesh_exe = mesh_two
        else:
            mesh_exe = mesh

        mesh_attempts = 0
        mesh_retries = 20
        while 1:
            try:
                mesh_cmd = subprocess.run(
                    [mesh_exe, "-nodeidhex"], capture_output=True, timeout=30
                )
                mesh_node_id = mesh_cmd.stdout.decode("utf-8", errors="ignore").strip()
            except Exception:
                mesh_attempts += 1
                print(
                    f"Failed to get mesh node id: attempt {mesh_attempts} of {mesh_retries}",
                    flush=True,
                )
                sleep(5)
            else:
                if "not defined" in mesh_node_id.lower():
                    mesh_attempts += 1
                    print(
                        f"Failed to get mesh node id: attempt {mesh_attempts} of {mesh_retries}",
                        flush=True,
                    )
                    sleep(5)
                else:
                    mesh_attempts = 0

            if mesh_attempts == 0:
                break
            elif mesh_attempts > mesh_retries:
                self.mesh_success = False
                mesh_node_id = "error installing meshagent"
                break

        self.mesh_node_id = mesh_node_id
        self.logger.debug(f"Mesh node id: {mesh_node_id}")
        sys.stdout.flush()

        print("Adding agent to dashboard", flush=True)

        url = f"{self.api}/api/v1/add/"
        payload = {
            "agent_id": self.agent_id,
            "hostname": self.agent_hostname,
            "client": self.client_id,
            "site": self.site_id,
            "mesh_node_id": self.mesh_node_id,
            "description": self.agent_desc,
            "monitoring_type": self.agent_type,
        }
        self.logger.debug(payload)
        sys.stdout.flush()

        try:
            r = requests.post(
                url, json.dumps(payload), headers=self.headers, timeout=60
            )
        except Exception as e:
            self.logger.error(e)
            sys.stdout.flush()
            sys.exit(1)

        if r.status_code != 200:
            print("Error adding agent to dashboard", flush=True)
            sys.exit(1)

        self.agent_pk = r.json()["pk"]
        self.salt_id = f"{self.agent_hostname}-{self.agent_pk}"

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
                ).save()
        except Exception as e:
            print(f"Error creating database: {e}", flush=True)
            sys.exit(1)

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
            "salt-minion-setup.exe",
            "/S",
            "/custom-config=saltcustom",
            f"/master={self.salt_master}",
            f"/minion-name={self.salt_id}",
            "/start-minion=1",
        ]
        install_salt = subprocess.run(salt_cmd, cwd=self.programdir, shell=True)
        # give time for salt to fully install since the above command returns immmediately
        sleep(60)

        # accept the salt key on the master
        url = f"{self.api}/api/v1/acceptsaltkey/"
        payload = {"saltid": self.salt_id}
        accept_attempts = 0
        salt_retries = 20

        while 1:
            try:
                r = requests.post(
                    url, json.dumps(payload), headers=self.headers, timeout=30
                )
            except Exception as e:
                logger.debug(e)
                sys.stdout.flush()
                accept_attempts += 1
                sleep(5)
            else:
                if r.status_code != 200:
                    accept_attempts += 1
                    print(
                        f"Salt-key was not accepted: attempt {accept_attempts} of {salt_retries}",
                        flush=True,
                    )
                    sleep(5)
                else:
                    accept_attempts = 0

            if accept_attempts == 0:
                print("Salt-key was accepted!", flush=True)
                break
            elif accept_attempts > salt_retries:
                self.accept_success = False
                break

        print("Waiting for salt to sync with the master", flush=True)
        sleep(10)  # wait for salt to sync

        # sync our custom salt modules
        print("Syncing custom modules", flush=True)
        url = f"{self.api}/api/v1/firstinstall/"
        payload = {"pk": self.agent_pk}
        sync_attempts = 0
        sync_retries = 20

        while 1:
            try:
                r = requests.post(
                    url, json.dumps(payload), headers=self.headers, timeout=30
                )
            except Exception as e:
                self.logger.debug(e)
                sys.stdout.flush()
                sync_attempts += 1
                sleep(5)
            else:
                if r.status_code != 200:
                    sync_attempts += 1
                    print(
                        f"Syncing modules failed: attempt {sync_attempts} of {sync_retries}",
                        flush=True,
                    )
                    sleep(5)
                else:
                    sync_attempts = 0

            if sync_attempts == 0:
                print("Modules were synced!", flush=True)
                break
            elif sync_attempts > sync_retries:
                self.sync_success = False
                break

        sleep(10)  # wait a bit for modules to fully sync

        # create the scheduled tasks
        from agent import WindowsAgent

        try:
            agent = WindowsAgent()
            agent.create_fix_salt_task()
            agent.create_fix_mesh_task()
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
                self.tacticalrmm,
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
                self.tacticalrmm,
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

        # finish up
        if not self.accept_success:
            print("-" * 75, flush=True)
            print("ERROR: The RMM was unable to accept the salt minion.", flush=True)
            print("Salt may not have been properly installed.", flush=True)
            print("Try running the following command on the rmm:", flush=True)
            print(f"sudo salt-key -y -a '{self.salt_id}'", flush=True)
            print("-" * 75, flush=True)

        if not self.sync_success:
            print("-" * 75, flush=True)
            print("Unable to sync salt modules.", flush=True)
            print("Salt may not have been properly installed.", flush=True)
            print("-" * 75, flush=True)

        if not self.mesh_success:
            print("-" * 75, flush=True)
            print("The Mesh Agent was not installed properly.", flush=True)
            print("Some features will not work.", flush=True)
            print("-" * 75, flush=True)

        if self.accept_success and self.sync_success and self.mesh_success:
            print("Installation was successfull!", flush=True)
            print(
                "Allow a few minutes for the agent to properly display in the RMM",
                flush=True,
            )
        else:
            print("*****Installation finished with errors.*****", flush=True)
