import json
import os
import random
import re
import shutil
import socket
import string
import subprocess
from time import sleep
from urllib.parse import urlparse

import psutil
import requests
import validators

from agent import AgentStorage, db
from utils import kill_proc


class Installer:
    def __init__(self, api_url, client_id, site_id, agent_desc, agent_type, auth_token):
        self.api_url = api_url
        self.client_id = client_id
        self.site_id = site_id
        self.agent_desc = agent_desc
        self.agent_type = agent_type
        self.auth_token = auth_token
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

    def rand_string(self):
        chars = string.ascii_letters
        return "".join(random.choice(chars) for i in range(35))

    def install(self):
        # generate the agent id
        try:
            r = subprocess.run(
                ["wmic", "csproduct", "get", "uuid"], capture_output=True
            )
            wmic_id = r.stdout.decode().splitlines()[2].strip()
        except Exception:
            self.agent_id = f"{self.rand_string()}|{self.agent_hostname}"
        else:
            self.agent_id = f"{wmic_id}|{self.agent_hostname}"

        # validate the url and get the salt master
        r = urlparse(self.api_url)

        if r.scheme != "https" and r.scheme != "http":
            print("api url must contain https or http")
            raise SystemExit()

        if validators.domain(r.netloc):
            self.salt_master = r.netloc
        # will match either ipv4 , or ipv4:port
        elif re.match(r"[0-9]+(?:\.[0-9]+){3}(:[0-9]+)?", r.netloc):
            if validators.ipv4(r.netloc):
                self.salt_master = r.netloc
            else:
                self.salt_master = r.netloc.split(":")[0]
        else:
            print("Error parsing api url")
            raise SystemExit()

        # set the api base url
        self.api = f"{r.scheme}://{r.netloc}"

        # get the agent's token
        url = f"{self.api}/api/v1/token/"
        payload = {"agent_id": self.agent_id}
        r = requests.post(url, json.dumps(payload), headers=self.headers)

        if r.status_code == 401:
            print("Token has expired. Please generate a new one from the rmm.")
            raise SystemExit()
        elif r.status_code != 200:
            e = json.loads(r.text)["error"]
            print(e)
            raise SystemExit()
        else:
            self.agent_token = json.loads(r.text)["token"]

        # download salt
        print("Downloading salt minion")
        r = requests.get(
            "https://github.com/wh1te909/winagent/raw/master/bin/salt-minion-setup.exe",
            stream=True,
        )

        if r.status_code != 200:
            print("Unable to download salt-minion")
            raise SystemExit()

        minion = os.path.join(self.programdir, "salt-minion-setup.exe")
        with open(minion, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)

        del r

        # download mesh agent
        url = f"{self.api}/api/v1/getmeshexe/"
        r = requests.post(url, headers=self.headers, stream=True)

        if r.status_code != 200:
            print("Unable to download meshagent.")
            print("Please refer to the readme for instructions on how to upload it.")
            raise SystemExit()

        mesh = os.path.join(self.programdir, "meshagent.exe")

        with open(mesh, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)

        del r

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
            print("Found existing Mesh Agent. Removing...")
            try:
                subprocess.run(["sc", "stop", "mesh agent"], capture_output=True, timeout=30)
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

            r = subprocess.run(
                [mesh, "-fulluninstall"], capture_output=True, timeout=60
            )

            if os.path.exists(mesh_cleanup_dir):
                try:
                    shutil.rmtree(mesh_cleanup_dir)
                    sleep(1)
                    os.system('rmdir /S /Q "{}"'.format(mesh_cleanup_dir))
                except:
                    pass

        # install the mesh agent
        print("Installing mesh agent")
        ret = subprocess.run([mesh, "-fullinstall"], capture_output=True)
        sleep(10)

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
        while 1:
            try:
                mesh_cmd = subprocess.run([mesh_exe, "-nodeidhex"], capture_output=True)
                mesh_node_id = mesh_cmd.stdout.decode().strip()
            except Exception:
                mesh_attempts += 1
                sleep(5)
            else:
                if "not defined" in mesh_node_id.lower():
                    sleep(5)
                    mesh_attempts += 1
                else:
                    mesh_attempts = 0

            if mesh_attempts == 0:
                break
            elif mesh_attempts > 20:
                self.mesh_success = False
                mesh_node_id = "error installing meshagent"
                break

        self.mesh_node_id = mesh_node_id

        # add the agent to the dashboard
        print("Adding agent to dashboard")

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
        r = requests.post(url, json.dumps(payload), headers=self.headers)

        if r.status_code != 200:
            print("Error adding agent to dashboard")
            raise SystemExit()

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
            print(f"Error creating database: {e}")
            raise SystemExit()

        # install salt
        print("Installing salt")

        salt_cmd = [
            "salt-minion-setup.exe",
            "/S",
            "/custom-config=saltcustom",
            f"/master={self.salt_master}",
            f"/minion-name={self.salt_id}",
            "/start-minion=1",
        ]
        install_salt = subprocess.run(salt_cmd, cwd=self.programdir, shell=True)
        sleep(15)  # wait for salt to register on the master

        # accept the salt key on the master
        url = f"{self.api}/api/v1/acceptsaltkey/"
        payload = {"saltid": self.salt_id}
        accept_attempts = 0

        while 1:
            r = requests.post(url, json.dumps(payload), headers=self.headers)
            if r.status_code != 200:
                accept_attempts += 1
                sleep(5)
            else:
                accept_attempts = 0

            if accept_attempts == 0:
                break
            else:
                if accept_attempts > 20:
                    self.accept_success = False
                    break

        sleep(15)  # wait for salt to start

        # sync our custom salt modules
        url = f"{self.api}/api/v1/firstinstall/"
        payload = {"pk": self.agent_pk}
        sync_attempts = 0

        while 1:
            r = requests.post(url, json.dumps(payload), headers=self.headers)

            if r.status_code != 200:
                sync_attempts += 1
                sleep(5)
            else:
                sync_attempts = 0

            if sync_attempts == 0:
                break
            else:
                if sync_attempts > 20:
                    self.sync_success = False
                    break

        sleep(10)  # wait a bit for modules to fully sync

        # create the scheduled tasks
        from agent import WindowsAgent

        agent = WindowsAgent()
        agent.create_fix_salt_task()
        agent.create_fix_mesh_task()

        # remove services if they exists
        try:
            tac = psutil.win_service_get("tacticalagent")
        except psutil.NoSuchProcess:
            pass
        else:
            print("Found tacticalagent service. Removing...")
            subprocess.run([self.nssm, "stop", "tacticalagent"])
            subprocess.run([self.nssm, "remove", "tacticalagent", "confirm"])

        try:
            chk = psutil.win_service_get("checkrunner")
        except psutil.NoSuchProcess:
            pass
        else:
            print("Found checkrunner service. Removing...")
            subprocess.run([self.nssm, "stop", "checkrunner"])
            subprocess.run([self.nssm, "remove", "checkrunner", "confirm"])

        # install the windows services
        # winagent
        subprocess.run(
            [
                self.nssm,
                "install",
                "tacticalagent",
                self.tacticalrmm,
                "-m",
                "winagentsvc",
            ]
        )
        subprocess.run(
            [self.nssm, "set", "tacticalagent", "DisplayName", r"Tactical RMM Agent"]
        )
        subprocess.run(
            [self.nssm, "set", "tacticalagent", "Description", r"Tactical RMM Agent",]
        )
        subprocess.run([self.nssm, "start", "tacticalagent"])

        # checkrunner
        subprocess.run(
            [
                self.nssm,
                "install",
                "checkrunner",
                self.tacticalrmm,
                "-m",
                "checkrunner",
            ]
        )
        subprocess.run(
            [
                self.nssm,
                "set",
                "checkrunner",
                "DisplayName",
                r"Tactical RMM Check Runner",
            ]
        )
        subprocess.run(
            [
                self.nssm,
                "set",
                "checkrunner",
                "Description",
                r"Tactical RMM Check Runner",
            ]
        )
        subprocess.run([self.nssm, "start", "checkrunner"])

        # finish up
        if not self.accept_success:
            print("The RMM was unable to accept the salt minion.")
            print("Run the following command on the rmm:")
            print(f"sudo salt-key -y -a '{self.salt_id}'")

        if not self.sync_success:
            print("Unable to sync salt modules.")
            print("Salt may not have been properly installed.")

        if not self.mesh_success:
            print("The Mesh Agent was not installed properly.")
            print("Some features will not work.")

        if self.accept_success and self.sync_success and self.mesh_success:
            print("Installation was successfull.")
        else:
            print("Installation finished with errors.")
