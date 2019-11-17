import os
import sqlite3
import requests
import json
import shutil
from time import sleep

AGENT_DB = "C:\\Program Files\\TacticalAgent\\winagent\\agentdb.db"

def db_connect(db_path=AGENT_DB):
    con = sqlite3.connect(db_path)
    return con


con = db_connect()
cur = con.cursor()
cur.execute("SELECT agentid, token, server FROM agentstorage")
results = cur.fetchall()
agentid = results[0][0]
token = results[0][1]
server = results[0][2]
payload = {"agentid": agentid}
headers = {"content-type": "application/json", "Authorization": f"Token {token}"}

url = f"{server}/api/v1/deleteagent/"
requests.post(url, json.dumps(payload), headers=headers)


sleep(1)
try:
    shutil.rmtree("C:\\salt")
except Exception:
    pass
finally:
    sleep(1)

try:
    os.system('rmdir /S /Q "{}"'.format("C:\\salt"))
except Exception:
    pass
finally:
    sleep(1)

try:
    shutil.rmtree("C:\\salt")
except Exception:
    pass