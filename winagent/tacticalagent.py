import psutil
import PySimpleGUI as sg
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
import ctypes

from models import db, AgentStorage

HEADERS = {"content-type": "application/json"}


def rand_string(length):
    chars = string.ascii_letters
    return "".join(random.choice(chars) for i in range(length))


def install_agent():
    sg.SetOptions(font=("Helvetica", 12), icon=os.path.join(os.getcwd(), "onit.ico"))
    sg.ChangeLookAndFeel("Reddit")
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
        icon=os.path.join(os.getcwd(), "onit.ico"),
        default_element_size=(100, 23),
        default_button_element_size=(120, 50),
    ).Layout(auth_layout)

    while True:
        auth_event, auth_values = window_auth.Read()

        if auth_event is None:
            sg.Popup("Agent was not installed", background_color="red")
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
                    auth_url, auth=(auth_username, auth_pw), headers=HEADERS
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
                headers=HEADERS,
            )
            if twofactor_resp.status_code != 200:
                sg.Popup(json.loads(twofactor_resp.text))
                continue
            break

    window_auth.Close()

    # generate agent id
    agent_hostname = socket.gethostname()

    try:
        r = subprocess.run(["wmic", "csproduct", "get", "uuid"], capture_output=True)
        wmic_id = r.stdout.decode().splitlines()[2].strip()
    except Exception:
        unique_id = f"{rand_string(35)}|{agent_hostname}"
    else:
        unique_id = f"{wmic_id}|{agent_hostname}"

    try:
        client_resp = requests.get(
            f"{rmm_url}/clients/installer/listclients/",
            auth=(auth_username, auth_pw),
            headers=HEADERS,
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
            headers=HEADERS,
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
                sites, size=(25, 1), default_value=sites[0], key="site", readonly=True
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
        [sg.Text(f"Hostname: {agent_hostname}")],
        [sg.Frame("Install", final_layout)],
    ]

    window = sg.Window(
        "Tactical Agent Installation",
        size=(600, 400),
        icon=os.path.join(os.getcwd(), "onit.ico"),
    ).Layout(layout)

    while True:
        event, values = window.Read()
        selected_client = values["client"]

        if event is None:
            sg.Popup("Agent was not installed", background_color="red")
            raise SystemExit()
        elif event == "Install":
            nssm_client = selected_client
            nssm_site = values["site"]
            nssm_desc = values["desc"]
            if not (nssm_client and nssm_site and nssm_desc):
                sg.Popup("All fields are required!")
                continue

            break

        window.FindElement("site").Update(values=get_sites(selected_client))

    if values["server"]:
        nssm_type = "server"
    else:
        nssm_type = "workstation"

    window.Close()
    # rmm get token
    token_url = f"{rmm_url}/api/v1/token/"
    token_payload = {"agentid": unique_id}
    token_resp = requests.post(
        token_url,
        json.dumps(token_payload),
        auth=(auth_username, auth_pw),
        headers=HEADERS,
    )

    if token_resp.status_code != 200:
        error = json.loads(token_resp.text)["error"]
        sg.Popup(error)
        raise SystemExit()
    else:
        token = json.loads(token_resp.text)["token"]

    layout_install = [
        [sg.Text("Installing agent...this will take a while...", key="install_text")],
        [sg.ProgressBar(100, orientation="h", size=(20, 20), key="progressinstall")],
    ]

    window_install = sg.Window(
        "Tactical Agent Installer",
        size=(400, 60),
        icon=os.path.join(os.getcwd(), "onit.ico"),
    ).Layout(layout_install)
    event, values = window_install.Read(timeout=300)

    progress_bar_install = window_install.FindElement("progressinstall")

    progress_bar_install.UpdateBar(25)

    # install mesh agent
    get_mesh_exe = requests.post(
        f"{rmm_url}/api/v1/getmeshexe/",
        auth=(auth_username, auth_pw),
        headers=HEADERS,
        stream=True,
    )

    mesh_file = "C:\\Program Files\\TacticalAgent\\meshagent.exe"

    with open(mesh_file, "wb") as out_file:
        for chunk in get_mesh_exe.iter_content(chunk_size=1024):
            if chunk:
                out_file.write(chunk)

    del get_mesh_exe

    subprocess.run([mesh_file, "-fullinstall"])
    sleep(5)
    mesh_cmd = subprocess.run(
        ["C:\\Program Files\\Mesh Agent\\MeshAgent.exe", "-nodeidhex"],
        capture_output=True,
    )
    try:
        mesh_node_id = mesh_cmd.stdout.decode().strip()
    except Exception:
        mesh_node_id = "error installing meshagent"

    version_file = os.path.join(os.getcwd(), "VERSION")

    with open(version_file, "r") as vf:
        version = vf.read()

    add_headers = {
        "content-type": "application/json",
        "Authorization": f"Token {token}",
    }

    add_payload = {
        "agentid": unique_id,
        "hostname": agent_hostname,
        "client": nssm_client,
        "site": nssm_site,
        "mesh_node_id": mesh_node_id,
        "description": nssm_desc,
        "monitoring_type": nssm_type,
    }

    add_url = f"{rmm_url}/api/v1/add/"
    add_resp = requests.post(add_url, json.dumps(add_payload), headers=add_headers)

    if add_resp.status_code != 200:
        sg.Popup("Error during installation")
        raise SystemExit()

    agent_pk = add_resp.json()["pk"]

    try:
        with db:
            db.create_tables([AgentStorage])
            AgentStorage(
                server=rmm_url,
                agentid=unique_id,
                client=nssm_client,
                site=nssm_site,
                agent_type=nssm_type,
                description=nssm_desc,
                mesh_node_id=mesh_node_id,
                token=token,
                version=version,
                agentpk=agent_pk,
            ).save()
    except Exception as e:
        sg.Popup(e)

    subprocess.run(
        [
            "C:\\Program Files\\TacticalAgent\\salt-minion-setup.exe",
            "/S",
            "/custom-config=saltcustom",
            f"/master={salt_master}",
            f"/minion-name={agent_hostname}-{agent_pk}",
            "/start-minion=1",
        ],
        shell=True,
    )
    progress_bar_install.UpdateBar(30)

    sleep(30)  # wait for salt to register on master
    window_install.FindElement("install_text").Update("Registering with the RMM...")
    progress_bar_install.UpdateBar(70)

    salt_accept_url = f"{rmm_url}/api/v1/acceptsaltkey/"
    accept_payload = {"saltid": f"{agent_hostname}-{agent_pk}"}
    attempts = 0
    accept_success = True

    # make sure the salt minion is accepted on the master
    # if not, warn that must manually accept the salt-key
    while 1:
        salt_accept_resp = requests.post(
            salt_accept_url,
            json.dumps(accept_payload),
            auth=(auth_username, auth_pw),
            headers=HEADERS,
        )
        if salt_accept_resp.status_code != 200:
            attempts += 1
            sleep(5)
        else:
            attempts = 0

        if attempts == 0:
            break
        else:
            if attempts > 20:
                accept_success = False
                break

    sleep(15)  # wait for salt to start

    progress_bar_install.UpdateBar(75)
    window_install.FindElement("install_text").Update("Registering agent service...")

    # install services
    nssm = "C:\\Program Files\\TacticalAgent\\nssm.exe"
    install_dir = "C:\\Program Files\\TacticalAgent"

    # winagent
    subprocess.run(
        [nssm, "install", "tacticalagent", f"{install_dir}\\winagent\\winagentsvc.exe"]
    )
    subprocess.run([nssm, "set", "tacticalagent", "DisplayName", r"Tactical RMM Agent"])
    subprocess.run(
        [nssm, "set", "tacticalagent", "Description", r"Tactical RMM Monitoring Agent"]
    )
    subprocess.run([nssm, "start", "tacticalagent"])

    # checkrunner
    subprocess.run(
        [nssm, "install", "checkrunner", f"{install_dir}\\checkrunner\\checkrunner.exe"]
    )
    subprocess.run(
        [nssm, "set", "checkrunner", "DisplayName", r"Tactical Agent Check Runner"]
    )
    subprocess.run(
        [
            nssm,
            "set",
            "checkrunner",
            "Description",
            r"Tactical Agent Background Check Runner",
        ]
    )
    subprocess.run([nssm, "start", "checkrunner"])

    # winupdater
    subprocess.run(
        [nssm, "install", "winupdater", f"{install_dir}\\winupdater\\winupdater.exe"]
    )
    subprocess.run(
        [nssm, "set", "winupdater", "DisplayName", r"Tactical Agent Windows Update"]
    )
    subprocess.run(
        [
            nssm,
            "set",
            "winupdater",
            "Description",
            r"Tactical Agent Background Windows Update Service",
        ]
    )
    subprocess.run([nssm, "start", "winupdater"])

    window_install.Close()

    if not accept_success:
        accept_popup = "The RMM was unable to accept the salt minion\n"
        accept_popup += "Run the following command on the rmm:\n\n"
        accept_popup += f"sudo salt-key -y -a '{agent_hostname}-{agent_pk}'\n"
        sg.Popup(accept_popup)
        sg.Popup("Installation finished!")
    else:
        sg.Popup("Installation was successfull!")


def show_status():
    sg.SetOptions(font=("Helvetica", 12), icon=os.path.join(os.getcwd(), "onit.ico"))
    sg.ChangeLookAndFeel("Reddit")

    agent_status = psutil.win_service_get("tacticalagent").status()
    salt_status = psutil.win_service_get("salt-minion").status()

    status_layout = [
        [sg.Text("Agent status: "), sg.Text(agent_status, key="agentstatus"),],
        [sg.Text("Salt minion status: "), sg.Text(salt_status, key="saltstatus"),],
    ]

    window_status = sg.Window(
        "Tactical Agent", size=(300, 100), icon=os.path.join(os.getcwd(), "onit.ico"),
    ).Layout(status_layout)

    while True:
        event, values = window_status.Read()

        if event is None:
            window_status.Close()
            raise SystemExit()


if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        sg.Popup("Must be run as administrator!")
        raise SystemExit()

    try:
        service = psutil.win_service_get("tacticalagent")
    except psutil.NoSuchProcess:
        install_agent()
    else:
        show_status()
