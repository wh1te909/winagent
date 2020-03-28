import PySimpleGUI as sg
import psutil
import json
import requests
import subprocess
import os
from time import sleep
import socket
import validators
import re
import random
import string

from agent import db, AgentStorage


class Installer:
    def __init__(self):
        self.programdir = "C:\\Program Files\\TacticalAgent"
        self.headers = {"content-type": "application/json"}
        self.icon = os.path.join(self.programdir, "onit.ico")
        self.agent_hostname = socket.gethostname()
        self.version = self.get_version()
        self.set_theme()
        self.nssm = os.path.join(self.programdir, "nssm.exe")
        self.tacticalrmm = os.path.join(self.programdir, "tacticalrmm.exe")
        self.rmm_url = ""
        self.auth_username = ""
        self.auth_pw = ""
        self.salt_master = ""
        self.salt_id = ""
        self.unique_id = ""
        self.token = ""
        self.agent_client = ""
        self.agent_site = ""
        self.mesh_node_id = ""
        self.agent_desc = ""
        self.agent_type = ""
        self.token_headers = {}
        self.agent_pk = 0
        self.mesh_success = True
        self.accept_success = True
        self.sync_success = True

    def set_theme(self):
        sg.SetOptions(font=("Helvetica", 12), icon=self.icon)
        sg.ChangeLookAndFeel("Reddit")

    def rand_string(self):
        chars = string.ascii_letters
        return "".join(random.choice(chars) for i in range(35))

    def get_version(self):
        version_file = os.path.join(self.programdir, "VERSION")
        with open(version_file, "r") as vf:
            version = vf.read()

        return version

    def pre_install(self):
        auth_layout = [
            [sg.Text("RMM Url:")],
            [
                sg.InputCombo(
                    ["https://", "http://"],
                    size=(6, 1),
                    default_value="https://",
                    readonly=True,
                    key="protocol",
                ),
                sg.InputText("", key="rmmurl"),
            ],
            [sg.Text("Username:")],
            [sg.InputText("", key="authusername")],
            [sg.Text("Password:")],
            [sg.InputText("", key="authpassword", password_char="*")],
            [sg.Submit("Authorize", size=(40, 1))],
        ]
        window_auth = sg.Window(
            "Tactical RMM Installer",
            size=(400, 250),
            font=("Helvetica", 12),
            element_padding=(2, 3),
            icon=self.icon,
            default_element_size=(100, 23),
            default_button_element_size=(120, 50),
        ).Layout(auth_layout)

        while True:
            auth_event, auth_values = window_auth.Read()

            if auth_event is None:
                raise SystemExit()
            elif auth_event == "Authorize":
                ip_or_port = re.match(
                    r"[0-9]+(?:\.[0-9]+){3}(:[0-9]+)?", auth_values["rmmurl"]
                )
                if not validators.domain(auth_values["rmmurl"]) and not ip_or_port:
                    validation_error = (
                        "ERROR: Please enter a valid domain name or IPv4 address\n\n"
                    )
                    validation_error += (
                        "Examples:\n\n10.0.10.1\napi.example.com\n10.0.10.1:8000"
                    )
                    validation_error += "\n\nDo NOT put trailing slashes!\n"
                    sg.Popup(validation_error)
                    continue
                if ip_or_port:
                    ip_stripped = auth_values["rmmurl"].split(":")[0]
                    if not validators.ipv4(ip_stripped):
                        sg.Popup("Error parsing IP address")
                        continue
                    salt_master = ip_stripped
                else:
                    salt_master = auth_values["rmmurl"]

                rmm_url = auth_values["protocol"] + auth_values["rmmurl"]
                auth_username = auth_values["authusername"]
                auth_pw = auth_values["authpassword"]
                if not (rmm_url and auth_username and auth_pw):
                    sg.Popup("All fields are required!")
                    continue

                # rmm basic auth
                auth_url = f"{rmm_url}/api/v1/agentauth/"
                try:

                    auth_resp = requests.post(
                        auth_url, auth=(auth_username, auth_pw), headers=self.headers
                    )
                except Exception:
                    sg.Popup("Unable to contact the RMM.")
                    continue
                if auth_resp.status_code != 200:
                    sg.Popup("Bad username or password")
                    continue

                # 2 factor verify
                twofactor_token = sg.PopupGetText(
                    "Please enter your google authenticator code",
                    "2 factor",
                    size=(40, 25),
                )
                twofactor_payload = {"twofactorToken": twofactor_token}
                two_factor_url = f"{rmm_url}/installer/twofactor/"
                twofactor_resp = requests.post(
                    two_factor_url,
                    json.dumps(twofactor_payload),
                    auth=(auth_username, auth_pw),
                    headers=self.headers,
                )
                if twofactor_resp.status_code != 200:
                    sg.Popup(json.loads(twofactor_resp.text))
                    continue
                break

        window_auth.Close()

        # generate agent id
        try:
            r = subprocess.run(
                ["wmic", "csproduct", "get", "uuid"], capture_output=True
            )
            wmic_id = r.stdout.decode().splitlines()[2].strip()
        except Exception:
            unique_id = f"{self.rand_string()}|{self.agent_hostname}"
        else:
            unique_id = f"{wmic_id}|{self.agent_hostname}"

        try:
            client_resp = requests.get(
                f"{rmm_url}/clients/installer/listclients/",
                auth=(auth_username, auth_pw),
                headers=self.headers,
            )
        except Exception:
            sg.Popup("Unable to contact the RMM. Please check your internet connection")
            raise SystemExit()
        else:
            clients_data = json.loads(client_resp.text)
            clients = [client["client"] for client in clients_data]

        def get_sites(client):
            sites_resp = requests.get(
                f"{rmm_url}/clients/installer/{client}/sites/",
                auth=(auth_username, auth_pw),
                headers=self.headers,
            )
            sites_data = json.loads(sites_resp.text)
            sites = [site["site"] for site in sites_data]
            return sites

        try:
            first_client = clients[0]
        except IndexError:
            sg.Popup("Please first add a client in the RMM web portal")
            raise SystemExit()
        sites = get_sites(first_client)

        description_layout = [
            [sg.Text("Enter a Short Description:")],
            [sg.InputText("", key="desc")],
        ]

        client_site_layout = [
            [sg.Text("Please select a client")],
            [
                sg.InputCombo(
                    clients,
                    size=(25, 1),
                    default_value=first_client,
                    enable_events=True,
                    readonly=True,
                    key="client",
                )
            ],
            [sg.Text("Please select a site")],
            [
                sg.InputCombo(
                    sites,
                    size=(25, 1),
                    default_value=sites[0],
                    key="site",
                    readonly=True,
                )
            ],
        ]

        mon_type_layout = [
            [
                sg.Text(
                    "Choose a monitoring type:",
                    tooltip="Server or Workstation affects default alert policy",
                )
            ],
            [
                sg.Radio("Server", "RADIO1", default=True, key="server"),
                sg.Radio("Workstation", "RADIO1", key="workstation"),
            ],
        ]

        final_layout = [[sg.Submit("Install", size=(60, 1))]]

        layout = [
            [sg.Frame("Client", client_site_layout)],
            [sg.Frame("Description", description_layout)],
            [sg.Frame("Monitoring Mode", mon_type_layout)],
            [sg.Text(f"Hostname: {self.agent_hostname}")],
            [sg.Frame("Install", final_layout)],
        ]

        window = sg.Window(
            "Tactical Agent Installation", size=(600, 400), icon=self.icon,
        ).Layout(layout)

        while True:
            event, values = window.Read()
            selected_client = values["client"]

            if event is None:
                raise SystemExit()
            elif event == "Install":
                agent_client = selected_client
                agent_site = values["site"]
                agent_desc = values["desc"]
                if not (agent_client and agent_site and agent_desc):
                    sg.Popup("All fields are required!")
                    continue

                break

            window.FindElement("site").Update(values=get_sites(selected_client))

        if values["server"]:
            agent_type = "server"
        else:
            agent_type = "workstation"

        window.Close()
        # rmm get token
        token_url = f"{rmm_url}/api/v1/token/"
        token_payload = {"agentid": unique_id}
        token_resp = requests.post(
            token_url,
            json.dumps(token_payload),
            auth=(auth_username, auth_pw),
            headers=self.headers,
        )

        if token_resp.status_code != 200:
            error = json.loads(token_resp.text)["error"]
            sg.Popup(error)
            raise SystemExit()
        else:
            token = json.loads(token_resp.text)["token"]

        self.rmm_url = rmm_url
        self.auth_username = auth_username
        self.auth_pw = auth_pw
        self.salt_master = salt_master
        self.unique_id = unique_id
        self.token = token
        self.agent_client = agent_client
        self.agent_site = agent_site
        self.agent_desc = agent_desc
        self.agent_type = agent_type
        self.token_headers = {
            "content-type": "application/json",
            "Authorization": f"Token {token}",
        }

    def download_salt(self, gui_queue):
        print("Downloading salt minion...")
        get_minion = requests.get(
            "https://github.com/wh1te909/winagent/raw/master/bin/salt-minion-setup.exe",
            stream=True,
        )

        if get_minion.status_code != 200:
            print("ERROR: Unable to download salt-minion")
            print("Please check your internet connection")
            gui_queue.put("installerror")
            return False

        minion_file = os.path.join(self.programdir, "salt-minion-setup.exe")
        with open(minion_file, "wb") as mout_file:
            for mchunk in get_minion.iter_content(chunk_size=1024):
                if mchunk:
                    mout_file.write(mchunk)

        del get_minion
        return True

    def install_mesh(self, gui_queue):
        print("Installing mesh agent...")
        get_mesh_exe = requests.post(
            f"{self.rmm_url}/api/v1/getmeshexe/",
            auth=(self.auth_username, self.auth_pw),
            headers=self.headers,
            stream=True,
        )

        if get_mesh_exe.status_code != 200:
            print("ERROR: Unable to download meshagent.exe")
            print("Please refer to the readme for instructions on how to upload it")
            gui_queue.put("installerror")
            return False

        mesh_file = os.path.join(self.programdir, "meshagent.exe")

        with open(mesh_file, "wb") as out_file:
            for chunk in get_mesh_exe.iter_content(chunk_size=1024):
                if chunk:
                    out_file.write(chunk)

        del get_mesh_exe

        subprocess.run([mesh_file, "-fullinstall"])
        sleep(10)

        mesh_attempts = 0
        while 1:
            try:
                mesh_cmd = subprocess.run(
                    ["C:\\Program Files\\Mesh Agent\\MeshAgent.exe", "-nodeidhex"],
                    capture_output=True,
                )
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
        return True

    def add_to_dashboard(self, gui_queue):
        print("Adding agent to dashboard...")
        add_payload = {
            "agentid": self.unique_id,
            "hostname": self.agent_hostname,
            "client": self.agent_client,
            "site": self.agent_site,
            "mesh_node_id": self.mesh_node_id,
            "description": self.agent_desc,
            "monitoring_type": self.agent_type,
        }

        add_url = f"{self.rmm_url}/api/v1/add/"
        add_resp = requests.post(
            add_url, json.dumps(add_payload), headers=self.token_headers
        )

        if add_resp.status_code != 200:
            print("ERROR: Agent not able to contact the rmm")
            gui_queue.put("installerror")
            return False

        agent_pk = add_resp.json()["pk"]
        self.agent_pk = agent_pk
        self.salt_id = f"{self.agent_hostname}-{self.agent_pk}"

        try:
            with db:
                db.create_tables([AgentStorage])
                AgentStorage(
                    server=self.rmm_url,
                    agentid=self.unique_id,
                    client=self.agent_client,
                    site=self.agent_site,
                    agent_type=self.agent_type,
                    description=self.agent_desc,
                    mesh_node_id=self.mesh_node_id,
                    token=self.token,
                    version=self.version,
                    agentpk=self.agent_pk,
                    salt_master=self.salt_master,
                    salt_id=self.salt_id,
                ).save()
        except Exception as e:
            print(f"ERROR: {e}")
            gui_queue.put("installerror")
            return False

        return True

    def install_salt(self):
        print("Installing salt...")
        subprocess.run(
            [
                os.path.join(self.programdir, "salt-minion-setup.exe"),
                "/S",
                "/custom-config=saltcustom",
                f"/master={self.salt_master}",
                f"/minion-name={self.agent_hostname}-{self.agent_pk}",
                "/start-minion=1",
            ],
            shell=True,
        )

        print("Waiting for salt to register on the master...")
        sleep(30)

        salt_accept_url = f"{self.rmm_url}/api/v1/acceptsaltkey/"
        accept_payload = {"saltid": f"{self.agent_hostname}-{self.agent_pk}"}
        accept_attempts = 0

        # make sure the salt minion is accepted on the master
        # if not, warn that must manually accept the salt-key
        print("Performing first time setup tasks...")
        while 1:
            salt_accept_resp = requests.post(
                salt_accept_url, json.dumps(accept_payload), headers=self.token_headers,
            )
            if salt_accept_resp.status_code != 200:
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

        print("Waiting for salt to start...")
        sleep(20)  # wait for salt to start

        # make sure we sync modules before starting services
        sync_modules_url = f"{self.rmm_url}/api/v1/firstinstall/"
        sync_payload = {"pk": self.agent_pk}
        sync_attempts = 0

        while 1:
            sync_modules = requests.post(
                sync_modules_url, json.dumps(sync_payload), headers=self.token_headers,
            )
            if sync_modules.status_code != 200:
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

        print("Syncing modules...")
        sleep(30)  # wait a bit for modules to fully sync
        return True

    def install_services(self):
        print("Installing services...")

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
            [
                self.nssm,
                "set",
                "tacticalagent",
                "Description",
                r"Tactical RMM Monitoring Agent",
            ]
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
                r"Tactical Agent Check Runner",
            ]
        )
        subprocess.run(
            [
                self.nssm,
                "set",
                "checkrunner",
                "Description",
                r"Tactical Agent Background Check Runner",
            ]
        )
        subprocess.run([self.nssm, "start", "checkrunner"])

        # winupdater
        subprocess.run(
            [self.nssm, "install", "winupdater", self.tacticalrmm, "-m", "winupdater",]
        )
        subprocess.run(
            [
                self.nssm,
                "set",
                "winupdater",
                "DisplayName",
                r"Tactical Agent Windows Update",
            ]
        )
        subprocess.run(
            [
                self.nssm,
                "set",
                "winupdater",
                "Description",
                r"Tactical Agent Background Windows Update Service",
            ]
        )
        subprocess.run([self.nssm, "start", "winupdater"])
        return True

    def finish(self):
        if not self.accept_success:
            print("The RMM was unable to accept the salt minion")
            print("Run the following command on the rmm:")
            print(f"sudo salt-key -y -a '{self.agent_hostname}-{self.agent_pk}'")

        if not self.sync_success:
            print("Unable to sync salt modules.")
            print("Salt may not have been properly installed.")

        if not self.mesh_success:
            print("The Mesh Agent was not installed properly.")
            print("Some features will not work.")

        if self.accept_success and self.sync_success and self.mesh_success:
            print("Installation was successfull!")
        else:
            print("Installation finished with errors")

    def install_all(self, gui_queue):
        # lol
        if self.download_salt(gui_queue):
            if self.install_mesh(gui_queue):
                if self.add_to_dashboard(gui_queue):
                    if self.install_salt():
                        if self.install_services():
                            self.finish()
                            gui_queue.put("installfinished")


class AgentGUI:
    def __init__(self):
        self.icon = os.path.join(os.getcwd(), "onit.ico")
        self.set_theme()

    def set_theme(self):
        sg.SetOptions(font=("Helvetica", 12), icon=self.icon)
        sg.ChangeLookAndFeel("Reddit")

    def show_status(self):
        agent_status = psutil.win_service_get("tacticalagent").status()
        salt_status = psutil.win_service_get("salt-minion").status()
        check_status = psutil.win_service_get("checkrunner").status()
        updater_status = psutil.win_service_get("winupdater").status()

        status_layout = [
            [sg.Text("Agent status: "), sg.Text(agent_status)],
            [sg.Text("Salt minion status: "), sg.Text(salt_status)],
            [sg.Text("Checkrunner status: "), sg.Text(check_status)],
            [sg.Text("Winupdater status: "), sg.Text(updater_status)],
        ]

        window_status = sg.Window(
            "Tactical RMM", size=(300, 150), icon=self.icon,
        ).Layout(status_layout)

        while True:
            event, values = window_status.Read()

            if event is None:
                window_status.Close()
                raise SystemExit()
