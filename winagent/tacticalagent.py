import ctypes
import psutil
import requests
import json
import os
import PySimpleGUIQt as sg

from installer import installagent
from models import AgentStorage, db

HEADERS = {"content-type": "application/json"}


def create_auth_window():
    with db:
        server = AgentStorage.select()[0].server

    sg.SetOptions(font=("Helvetica", 12), icon=os.path.join(os.getcwd(), "onit.ico"))
    sg.ChangeLookAndFeel("Reddit")
    auth_layout = [
        [sg.Text("Username:")],
        [sg.InputText("", key="authusername")],
        [sg.Text("Password:")],
        [sg.InputText("", key="authpassword", password_char="*")],
        [sg.Submit("Login", size=(40, 1))],
    ]

    window_auth = sg.Window(
        "Tactical Agent",
        size=(200, 150),
        font=("Helvetica", 12),
        element_padding=(2, 3),
        icon=os.path.join(os.getcwd(), "onit.ico"),
        default_element_size=(100, 23),
        default_button_element_size=(120, 50),
    ).Layout(auth_layout)

    while True:
        auth_event, auth_values = window_auth.Read()

        if auth_event is None:
            raise SystemExit()

        elif auth_event == "Login":

            auth_username = auth_values["authusername"]
            auth_pw = auth_values["authpassword"]
            if not (auth_username and auth_pw):
                sg.Popup("All fields are required!")
                continue

            auth_url = f"{server}/api/v1/agentauth/"
            auth_resp = requests.post(
                auth_url, auth=(auth_username, auth_pw), headers=HEADERS
            )
            if auth_resp.status_code != 200:
                sg.Popup("Bad username or password")
                continue

            twofactor_token = sg.PopupGetText(
                "Please enter your google authenticator code",
                "2 factor",
                size=(200, 25),
            )
            twofactor_payload = {"twofactorToken": twofactor_token}
            two_factor_url = f"{server}/installer/twofactor/"
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


def create_status_window():
    sg.SetOptions(font=("Helvetica", 12), icon=os.path.join(os.getcwd(), "onit.ico"))
    sg.ChangeLookAndFeel("Reddit")

    agent_status = psutil.win_service_get("tacticalagent").status()
    salt_status = psutil.win_service_get("salt-minion").status()

    status_layout = [
        [sg.Text("Agent status: "), sg.Text(agent_status, key="agentstatus"),],
        [sg.Text("Salt minion status: "), sg.Text(salt_status, key="saltstatus"),],
    ]

    window_status = sg.Window(
        "Tactical Agent",
        size=(400, 200),
        font=("Helvetica", 12),
        icon=os.path.join(os.getcwd(), "onit.ico"),
    ).Layout(status_layout)

    while True:
        event, values = window_status.Read()

        if event is None:
            window_status.Close()
            raise SystemExit()


if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        sg.Popup("Please re-run this script as admin. Exiting...")
        raise SystemExit()

    try:
        service = psutil.win_service_get("tacticalagent")
    except psutil.NoSuchProcess:
        installagent()
    else:
        create_auth_window()
        create_status_window()
