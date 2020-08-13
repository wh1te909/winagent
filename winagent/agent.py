import asyncio
import datetime as dt
import json
import logging
import math
import os
import platform
import shutil
import signal
import socket
import subprocess
from collections import defaultdict
from time import perf_counter, sleep

import peewee
import psutil
import requests
import validators
import win32con
import win32evtlog
import win32evtlogutil
import winerror
import wmi
from win32com.client import GetObject

from utils import (
    bytes2human,
    get_os_version_info,
    get_windows_os_release_grain,
    kill_proc,
)

db = peewee.SqliteDatabase("C:\\Program Files\\TacticalAgent\\agentdb.db")


class AgentStorage(peewee.Model):
    server = peewee.CharField()
    agentid = peewee.CharField()
    mesh_node_id = peewee.CharField()
    token = peewee.CharField()
    agentpk = peewee.IntegerField()
    salt_master = peewee.CharField()
    salt_id = peewee.CharField()

    class Meta:
        database = db


class WindowsAgent:
    def __init__(self):
        self.hostname = socket.gethostname()
        self.platform = platform.system().lower()
        self.astor = self.get_db()
        self.programdir = "C:\\Program Files\\TacticalAgent"
        self.exe = os.path.join(self.programdir, "tacticalrmm.exe")
        self.nssm = os.path.join(self.programdir, "nssm.exe")
        self.salt_call = "C:\\salt\\salt-call.bat"
        self.headers = {
            "content-type": "application/json",
            "Authorization": f"Token {self.astor.token}",
        }
        logging.basicConfig(
            filename=os.path.join(self.programdir, "winagent.log"),
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
        self.logger = logging.getLogger(__name__)
        self.salt_minion_exe = (
            "https://github.com/wh1te909/winagent/raw/master/bin/salt-minion-setup.exe"
        )

    @property
    def version(self):
        try:
            with open(os.path.join(self.programdir, "VERSION")) as f:
                ver = f.read().strip()

            return ver
        except:
            return "0.0.1"

    async def script_check(self, data):

        try:
            script_path = data["script"]["filepath"]
            shell = data["script"]["shell"]
            timeout = data["timeout"]
            script_filename = data["script"]["filename"]

            if shell == "python":
                cmd = [
                    self.salt_call,
                    "win_agent.run_python_script",
                    script_filename,
                    f"timeout={timeout}",
                ]
            else:
                cmd = [
                    self.salt_call,
                    "cmd.script",
                    script_path,
                    f"shell={shell}",
                    f"timeout={timeout}",
                ]

            start = perf_counter()

            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            proc_timeout = int(timeout) + 2

            try:
                proc_stdout, proc_stderr = await asyncio.wait_for(
                    proc.communicate(), proc_timeout
                )
            except asyncio.TimeoutError:
                try:
                    proc.terminate()
                except:
                    pass

                self.logger.error(f"Script check timed out after {timeout} seconds")
                proc_stdout, proc_stderr = False, False
                stdout = ""
                stderr = f"Script timed out after {timeout} seconds"
                retcode = 98

            stop = perf_counter()

            if proc_stdout:
                resp = json.loads(proc_stdout.decode("utf-8", errors="ignore"))
                retcode = resp["local"]["retcode"]
                stdout = resp["local"]["stdout"]
                stderr = resp["local"]["stderr"]

            elif proc_stderr:
                retcode = 99
                stdout = ""
                stderr = proc_stderr.decode("utf-8", errors="ignore")

            if retcode != 0:
                status = "failing"
            else:
                status = "passing"

            payload = {
                "stdout": stdout,
                "stderr": stderr,
                "status": status,
                "retcode": retcode,
                "execution_time": "{:.4f}".format(round(stop - start)),
            }

            resp = requests.patch(
                f"{self.astor.server}/api/v1/{data['id']}/checkrunner/",
                json.dumps(payload),
                headers=self.headers,
                timeout=15,
            )

            if (
                status == "failing"
                and data["assigned_task"]
                and data["assigned_task"]["enabled"]
            ):
                from taskrunner import TaskRunner

                task = TaskRunner(task_pk=data["assigned_task"]["id"])
                await task.run_while_in_event_loop()

            return status
        except:
            return "failing"

    async def ping_check(self, data):
        try:
            cmd = ["ping", data["ip"]]
            r = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await r.communicate()

            success = ["Reply", "bytes", "time", "TTL"]

            if stdout:
                output = stdout.decode("utf-8", errors="ignore")
                if all(x in output for x in success):
                    status = "passing"
                else:
                    status = "failing"

            elif stderr:
                status = "failing"
                output = stderr.decode("utf-8", errors="ignore")

            payload = {
                "status": status,
                "more_info": output,
            }

            resp = requests.patch(
                f"{self.astor.server}/api/v1/{data['id']}/checkrunner/",
                json.dumps(payload),
                headers=self.headers,
                timeout=15,
            )

            if (
                status == "failing"
                and data["assigned_task"]
                and data["assigned_task"]["enabled"]
            ):
                from taskrunner import TaskRunner

                task = TaskRunner(task_pk=data["assigned_task"]["id"])
                await task.run_while_in_event_loop()

            return status
        except:
            return "failing"

    async def disk_check(self, data, exists=True):
        try:
            disk = psutil.disk_usage(data["disk"])
        except Exception:
            exists = False
            self.logger.error(f"Disk {data['disk']} does not exist")

        if exists:
            percent_used = round(disk.percent)
            total = bytes2human(disk.total)
            free = bytes2human(disk.free)

            if (100 - percent_used) < data["threshold"]:
                status = "failing"
            else:
                status = "passing"

            more_info = f"Total: {total}B, Free: {free}B"
        else:
            status = "failing"
            more_info = f"Disk {data['disk']} does not exist"

        payload = {
            "status": status,
            "more_info": more_info,
        }

        resp = requests.patch(
            f"{self.astor.server}/api/v1/{data['id']}/checkrunner/",
            json.dumps(payload),
            headers=self.headers,
            timeout=15,
        )

        if (
            status == "failing"
            and data["assigned_task"]
            and data["assigned_task"]["enabled"]
        ):
            from taskrunner import TaskRunner

            task = TaskRunner(task_pk=data["assigned_task"]["id"])
            await task.run_while_in_event_loop()

        return status

    async def cpu_load_check(self, data):
        try:
            psutil.cpu_percent(interval=0)
            await asyncio.sleep(5)
            cpu_load = round(psutil.cpu_percent(interval=0))

            payload = {"percent": cpu_load}

            resp = requests.patch(
                f"{self.astor.server}/api/v1/{data['id']}/checkrunner/",
                json.dumps(payload),
                headers=self.headers,
                timeout=15,
            )

            return "ok"
        except:
            return False

    async def mem_check(self, data):
        try:

            payload = {"percent": self.get_used_ram()}

            resp = requests.patch(
                f"{self.astor.server}/api/v1/{data['id']}/checkrunner/",
                json.dumps(payload),
                headers=self.headers,
                timeout=15,
            )

            return "ok"
        except:
            return False

    async def win_service_check(self, data, exists=True):
        try:
            services = self.get_services()

            try:
                service = list(
                    filter(lambda x: x["name"] == data["svc_name"], services)
                )[0]
            except IndexError:
                exists = False
                self.logger.error(f"Service {data['svc_name']} does not exist")

            if exists:
                service_status = service["status"]

                if service_status == "running":
                    status = "passing"

                elif (
                    service_status == "start_pending" and data["pass_if_start_pending"]
                ):
                    status = "passing"

                else:
                    status = "failing"

                    if data["restart_if_stopped"]:
                        ret = self.salt_call_ret_bool(
                            cmd="service.restart", args=[data["svc_name"]], timeout=60,
                        )
                        # wait a bit to give service time to start before checking status again
                        await asyncio.sleep(10)
                        reloaded = self.get_services()
                        stat = list(
                            filter(lambda x: x["name"] == data["svc_name"], reloaded)
                        )[0]["status"]

                        if stat == "running":
                            status = "passing"
                        elif stat == "start_pending" and data["pass_if_start_pending"]:
                            status = "passing"
                        else:
                            status = "failing"

                        service_status = stat
            else:
                status = "failing"

            payload = {
                "status": status,
                "more_info": f"Status {service_status.upper()}"
                if exists
                else f"Service {data['svc_name']} does not exist",
            }

            resp = requests.patch(
                f"{self.astor.server}/api/v1/{data['id']}/checkrunner/",
                json.dumps(payload),
                headers=self.headers,
                timeout=15,
            )

            if (
                status == "failing"
                and data["assigned_task"]
                and data["assigned_task"]["enabled"]
            ):
                from taskrunner import TaskRunner

                task = TaskRunner(task_pk=data["assigned_task"]["id"])
                await task.run_while_in_event_loop()

            return status
        except:
            return "failing"

    async def event_log_check(self, data):
        try:
            log = []

            api_log_name = data["log_name"]
            api_event_id = int(data["event_id"])
            api_event_type = data["event_type"]
            api_fail_when = data["fail_when"]
            api_search_last_days = int(data["search_last_days"])

            if api_search_last_days != 0:
                start_time = dt.datetime.now() - dt.timedelta(days=api_search_last_days)

            flags = (
                win32evtlog.EVENTLOG_BACKWARDS_READ
                | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            )

            status_dict = {
                win32con.EVENTLOG_AUDIT_FAILURE: "AUDIT_FAILURE",
                win32con.EVENTLOG_AUDIT_SUCCESS: "AUDIT_SUCCESS",
                win32con.EVENTLOG_INFORMATION_TYPE: "INFO",
                win32con.EVENTLOG_WARNING_TYPE: "WARNING",
                win32con.EVENTLOG_ERROR_TYPE: "ERROR",
                0: "INFO",
            }

            hand = win32evtlog.OpenEventLog("localhost", api_log_name)
            total = win32evtlog.GetNumberOfEventLogRecords(hand)
            uid = 0
            done = False

            while 1:

                events = win32evtlog.ReadEventLog(hand, flags, 0)
                for ev_obj in events:

                    uid += 1
                    # return once total number of events reach or we'll be stuck in an infinite loop
                    if uid >= total:
                        done = True
                        break

                    the_time = ev_obj.TimeGenerated.Format()
                    time_obj = dt.datetime.strptime(the_time, "%c")

                    if api_search_last_days != 0:
                        if time_obj < start_time:
                            done = True
                            break

                    computer = str(ev_obj.ComputerName)
                    src = str(ev_obj.SourceName)
                    evt_type = str(status_dict[ev_obj.EventType])
                    evt_id = str(winerror.HRESULT_CODE(ev_obj.EventID))
                    evt_category = str(ev_obj.EventCategory)
                    record = str(ev_obj.RecordNumber)
                    msg = (
                        str(win32evtlogutil.SafeFormatMessage(ev_obj, api_log_name))
                        .replace("<", "")
                        .replace(">", "")
                    )

                    event_dict = {
                        "computer": computer,
                        "source": src,
                        "eventType": evt_type,
                        "eventID": evt_id,
                        "eventCategory": evt_category,
                        "message": msg,
                        "time": the_time,
                        "record": record,
                        "uid": uid,
                    }

                    if int(evt_id) == api_event_id and evt_type == api_event_type:
                        log.append(event_dict)

                if done:
                    break

            win32evtlog.CloseEventLog(hand)

            if api_fail_when == "contains":
                if log:
                    status = "failing"
                    more_info = {"log": log}
                else:
                    status = "passing"
                    more_info = {"log": []}

            elif api_fail_when == "not_contains":
                if log:
                    status = "passing"
                    more_info = {"log": log}
                else:
                    status = "failing"
                    more_info = {"log": []}
            else:
                status = "failing"
                more_info = {"log": []}

            payload = {
                "status": status,
                "extra_details": more_info,
            }

            resp = requests.patch(
                f"{self.astor.server}/api/v1/{data['id']}/checkrunner/",
                json.dumps(payload),
                headers=self.headers,
                timeout=15,
            )

            if (
                status == "failing"
                and data["assigned_task"]
                and data["assigned_task"]["enabled"]
            ):
                from taskrunner import TaskRunner

                task = TaskRunner(task_pk=data["assigned_task"]["id"])
                await task.run_while_in_event_loop()

            return status
        except Exception as e:
            self.logger.error(f"Event log check failed: {e}")
            return "failing"

    def get_db(self):
        with db:
            astor = AgentStorage.select()[0]

        return astor

    def get_boot_time(self):
        return psutil.boot_time()

    def get_used_ram(self):
        return round(psutil.virtual_memory().percent)

    def get_services(self):
        return [svc.as_dict() for svc in psutil.win_service_iter()]

    def get_total_ram(self):
        return math.ceil((psutil.virtual_memory().total / 1_073_741_824))

    def get_logged_on_user(self):
        try:
            return psutil.users()[0].name
        except Exception:
            return "None"

    def get_public_ip(self):
        try:
            ifconfig = requests.get("https://ifconfig.co/ip", timeout=5).text.strip()

            if not validators.ipv4(ifconfig) and not validators.ipv6(ifconfig):
                icanhaz = requests.get("https://icanhazip.com", timeout=7).text.strip()

                if not validators.ipv4(icanhaz) and not validators.ipv6(icanhaz):
                    return "error"
                else:
                    return icanhaz
            else:
                return ifconfig

        except Exception:
            return "error"

    def get_cmd_output(self, cmd, timeout=30):
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        except Exception:
            return "error getting output"

        if r.stdout:
            return r.stdout.decode("utf-8", errors="ignore")
        elif r.stderr:
            return r.stderr.decode("utf-8", errors="ignore")
        else:
            return "error getting output"

    def get_os(self):
        try:
            os = wmi.WMI().Win32_OperatingSystem()[0]
            return (
                f"{os.Caption}, {platform.architecture()[0]} (build {os.BuildNumber})"
            )
        except Exception:
            return "unknown-os"

    def get_disks(self):
        disks = defaultdict(dict)
        try:
            for part in psutil.disk_partitions(all=False):
                if os.name == "nt":
                    if "cdrom" in part.opts or part.fstype == "":
                        continue
                usage = psutil.disk_usage(part.mountpoint)
                device = part.device.split("\\", 1)[0]
                disks[device]["device"] = device
                disks[device]["total"] = bytes2human(usage.total)
                disks[device]["used"] = bytes2human(usage.used)
                disks[device]["free"] = bytes2human(usage.free)
                disks[device]["percent"] = int(usage.percent)
                disks[device]["fstype"] = part.fstype
        except Exception:
            disks = {"error": "error getting disk info"}

        return disks

    def get_platform_release(self):
        try:
            os = get_os_version_info()
            grains = get_windows_os_release_grain(os["Caption"], os["ProductType"])
            plat = platform.system().lower()
            plat_release = f"{plat}-{grains}"
        except Exception:
            plat_release = "unknown-release"

        return plat_release

    def get_av(self):
        r = subprocess.run(
            [
                "wmic",
                "/Namespace:\\\\root\SecurityCenter2",
                "Path",
                "AntiVirusProduct",
                "get",
                "displayName" "/FORMAT:List",
            ],
            capture_output=True,
            timeout=30,
        )

        if r.stdout:
            out = r.stdout.decode("utf-8", errors="ignore").lower().replace(" ", "").splitlines()
            out[:] = [i for i in out if i != ""]  # remove empty list items

            if len(out) == 1 and out[0] == "displayname=windowsdefender":
                return "windowsdefender"

            elif len(out) == 2:
                if "displayname=windowsdefender" in out:
                    out.remove("displayname=windowsdefender")
                    return out[0].split("displayname=", 1)[1]

            return "n/a"

        elif r.stderr:
            return "n/a"
        else:
            return "n/a"

    def salt_call_ret_bool(self, cmd, args=[], timeout=30):
        assert isinstance(args, list)
        try:
            command = [self.salt_call, cmd, "--local", f"--timeout={timeout}"]

            if args:
                # extend list at 3rd position
                command[2:2] = args

            r = subprocess.run(command, capture_output=True, timeout=timeout)
        except Exception:
            return False
        else:
            try:
                ret = json.loads(r.stdout.decode("utf-8", errors="ignore"))
                if ret["local"]:
                    return True
                else:
                    return False
            except:
                return False

    def get_salt_version(self):
        cmd = [self.salt_call, "pkg.list_pkgs", "--local", "--timeout=45"]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=50)
            ret = json.loads(r.stdout.decode("utf-8", errors="ignore"))
            ver = [
                (k, v) for k, v in ret["local"].items() if "salt minion" in k.lower()
            ][0][1]
        except:
            return False
        else:
            return ver

    def update_salt(self):
        try:
            salt_info = f"{self.astor.server}/api/v1/{self.astor.agentpk}/saltinfo/"
            r = requests.get(salt_info, headers=self.headers, timeout=15)
            if r.status_code != 200:
                return

            try:
                current_ver = r.json()["currentVer"]
                latest_ver = r.json()["latestVer"]
                salt_id = r.json()["salt_id"]
            except Exception:
                return

            installed_ver = self.get_salt_version()
            if not isinstance(installed_ver, str):
                self.logger.error("Unable to get installed salt version. Aborting")
                return

            if latest_ver == installed_ver:
                return

            self.logger.info("Updating salt")

            get_minion = requests.get(self.salt_minion_exe, stream=True, timeout=900)
            if get_minion.status_code != 200:
                self.logger.error("Unable to download salt-minion. Aborting")
                return False

            minion_file = os.path.join(self.programdir, "salt-minion-setup.exe")
            if os.path.exists(minion_file):
                os.remove(minion_file)

            sleep(1)
            with open(minion_file, "wb") as f:
                for chunk in get_minion.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)

            del get_minion

            p_stop = subprocess.run(
                [self.nssm, "stop", "checkrunner"], capture_output=True, timeout=60
            )

            r = subprocess.run(
                [
                    "salt-minion-setup.exe",
                    "/S",
                    "/custom-config=saltcustom",
                    f"/master={self.astor.salt_master}",
                    f"/minion-name={salt_id}",
                    "/start-minion=1",
                ],
                cwd=self.programdir,
                capture_output=True,
                shell=True,
                timeout=30,
            )
            sleep(60)

            p_start = subprocess.run(
                [self.nssm, "start", "checkrunner"], capture_output=True, timeout=60
            )

            payload = {"ver": latest_ver}
            r = requests.patch(
                salt_info, json.dumps(payload), headers=self.headers, timeout=30
            )

            self.logger.info(f"Salt was updated from {installed_ver} to {latest_ver}")
        except Exception as e:
            self.logger.error(e)

    def recover_salt(self):
        try:
            ssm = os.path.join("C:\\salt\\bin", "ssm.exe")
            r = subprocess.run(
                [ssm, "stop", "salt-minion"], capture_output=True, timeout=30
            )
            sleep(10)
            self.fix_salt(by_time=False)
            r = subprocess.run(
                ["ipconfig", "/flushdns"], capture_output=True, timeout=30
            )
            r = subprocess.run(
                [ssm, "start", "salt-minion"], capture_output=True, timeout=30
            )
        except Exception as e:
            self.logger.error(e)

    def recover_mesh(self):
        self._mesh_service_action("stop")
        sleep(5)
        pids = [
            proc.info
            for proc in psutil.process_iter(attrs=["pid", "name"])
            if "meshagent" in proc.info["name"].lower()
        ]

        for pid in pids:
            kill_proc(pid["pid"])

        mesh1 = os.path.join("C:\\Program Files\\Mesh Agent", "MeshAgent.exe")
        mesh2 = os.path.join(self.programdir, "meshagent.exe")
        if os.path.exists(mesh1):
            exe = mesh1
        else:
            exe = mesh2

        r = subprocess.run([exe, "-nodeidhex"], capture_output=True, timeout=30)
        if r.returncode != 0:
            self._mesh_service_action("start")
            return

        node_hex = r.stdout.decode("utf-8", errors="ignore").strip()
        if "not defined" in node_hex.lower():
            self._mesh_service_action("start")
            return

        try:
            mesh_info = f"{self.astor.server}/api/v1/{self.astor.agentpk}/meshinfo/"
            resp = requests.get(mesh_info, headers=self.headers, timeout=15)
        except Exception:
            self._mesh_service_action("start")
            return

        if resp.status_code == 200 and isinstance(resp.json(), str):
            if node_hex != resp.json():
                payload = {"nodeidhex": node_hex}
                requests.patch(
                    mesh_info, json.dumps(payload), headers=self.headers, timeout=15
                )

        self._mesh_service_action("start")

    def spawn_detached_process(self, cmd, shell=False):
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        DETACHED_PROCESS = 0x00000008
        p = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            shell=shell,
            creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
        )
        return p.pid

    def cleanup(self):
        self.cleanup_tasks()

        if os.path.exists("C:\\salt"):
            try:
                shutil.rmtree("C:\\salt")
                sleep(1)
                os.system('rmdir /S /Q "{}"'.format("C:\\salt"))
            except Exception:
                pass

    def fix_salt(self, by_time=True):
        """
        Script checks use salt-call, which for whatever reason becomes unstable after around 24 hours of uptime
        This leads to tons of hung python processes not being killed even with timeout set in salt's cmd.script module
        This function runs every hour as a scheduled task to clean up hung processes
        """

        # strings that will be in the scriptchecks command line args
        # we check to see if any of these are in our long running processes
        # we don't want to kill salt's main process, just the ones that have
        # any of the following args
        script_checks = (
            "win_agent.run_python_script",
            "salt-call",
            "userdefined",
            "salt://scripts",
            "cmd.script",
        )

        pids = []

        for proc in psutil.process_iter():
            with proc.oneshot():
                if proc.name() == "python.exe" or proc.name == "pythonw.exe":
                    if "salt" in proc.exe():
                        if any(_ in proc.cmdline() for _ in script_checks):
                            if by_time:
                                # psutil returns the process creation time as seconds since epoch
                                # convert it and the current local time now to utc so we can compare them
                                proc_ct = dt.datetime.fromtimestamp(
                                    proc.create_time()
                                ).replace(tzinfo=dt.timezone.utc)

                                utc_now = dt.datetime.now(dt.timezone.utc)

                                # seconds since the process was created
                                seconds = int(abs(utc_now - proc_ct).total_seconds())

                                # if process has been running for > 24 hours, need to kill it
                                if seconds > 86_400:
                                    pids.append(proc.pid)

                            else:
                                # if we are uninstalling, don't care about time.
                                # kill everything that's hung
                                pids.append(proc.pid)

        if pids:
            this_proc = os.getpid()
            for pid in pids:
                if pid == this_proc:
                    # don't kill myself
                    continue

                self.logger.warning(f"Killing salt pid: {pid}")
                kill_proc(pid)

    def _mesh_service_action(self, action):
        r = subprocess.run(
            ["sc", action, "mesh agent"], capture_output=True, timeout=30
        )

    def fix_mesh(self):
        """
        Mesh agent will randomly bug out and kill cpu usage
        This functions runs every hour as a scheduled task to solve that
        """
        mesh = [
            proc.info
            for proc in psutil.process_iter(attrs=["pid", "name"])
            if "meshagent" in proc.info["name"].lower()
        ]

        if mesh:
            try:
                proc = psutil.Process(mesh[0]["pid"])
            except psutil.NoSuchProcess:
                try:
                    self._mesh_service_action("stop")
                    sleep(3)
                    self._mesh_service_action("start")
                finally:
                    return

            cpu_usage = proc.cpu_percent(10) / psutil.cpu_count()

            if cpu_usage >= 18.0:
                self.logger.warning(
                    f"Mesh agent cpu usage: {cpu_usage}%. Restarting..."
                )
                self._mesh_service_action("stop")

                attempts = 0
                while 1:
                    svc = psutil.win_service_get("mesh agent")
                    if svc.status() != "stopped":
                        attempts += 1
                        sleep(1)
                    else:
                        attempts = 0

                    if attempts == 0 or attempts >= 30:
                        break

                # sometimes stopping service doesn't kill the hung proc
                mesh2 = [
                    proc.info
                    for proc in psutil.process_iter(attrs=["pid", "name"])
                    if "meshagent" in proc.info["name"].lower()
                ]

                if mesh2:
                    pids = []
                    for proc in mesh2:
                        pids.append(proc["pid"])

                    for pid in pids:
                        kill_proc(pid)

                    sleep(1)

                self._mesh_service_action("start")

    def create_fix_salt_task(self):

        start_obj = dt.datetime.now() + dt.timedelta(minutes=5)
        start_time = dt.datetime.strftime(start_obj, "%H:%M")

        cmd = [
            "name=TacticalRMM_fixsalt",
            "force=True",
            "action_type=Execute",
            f'cmd="{self.exe}"',
            "arguments='-m fixsalt'",
            "trigger_type=Daily",
            f"start_time='{start_time}'",
            "repeat_interval='1 hour'",
            "ac_only=False",
            "stop_if_on_batteries=False",
        ]

        return self.salt_call_ret_bool("task.create_task", args=cmd)

    def create_fix_mesh_task(self):

        start_obj = dt.datetime.now() + dt.timedelta(minutes=7)
        start_time = dt.datetime.strftime(start_obj, "%H:%M")

        cmd = [
            "name=TacticalRMM_fixmesh",
            "force=True",
            "action_type=Execute",
            f'cmd="{self.exe}"',
            "arguments='-m fixmesh'",
            "trigger_type=Daily",
            f"start_time='{start_time}'",
            "repeat_interval='1 hour'",
            "ac_only=False",
            "stop_if_on_batteries=False",
        ]

        return self.salt_call_ret_bool("task.create_task", args=cmd)

    def cleanup_tasks(self):
        r = subprocess.run(
            [self.salt_call, "task.list_tasks", "--local"], capture_output=True
        )

        ret = json.loads(r.stdout.decode("utf-8", "ignore"))["local"]

        tasks = [task for task in ret if task.startswith("TacticalRMM_")]

        if tasks:
            for task in tasks:
                try:
                    self.salt_call_ret_bool("task.delete_task", args=[task])
                except:
                    pass


def show_agent_status(window, gui):
    import win32api
    import win32con
    import win32gui
    import win32ts
    import win32ui

    class AgentStatus:
        def __init__(self, agent_status, salt_status, check_status, mesh_status):
            self.agent_status = agent_status
            self.salt_status = salt_status
            self.check_status = check_status
            self.mesh_status = mesh_status
            self.icon = os.path.join(os.getcwd(), "onit.ico")
            win32gui.InitCommonControls()
            self.hinst = win32api.GetModuleHandle(None)
            className = "AgentStatus"
            message_map = {
                win32con.WM_DESTROY: self.OnDestroy,
            }
            wc = win32gui.WNDCLASS()
            wc.style = win32con.CS_HREDRAW | win32con.CS_VREDRAW
            try:
                wc.hIcon = win32gui.LoadImage(
                    self.hinst,
                    self.icon,
                    win32con.IMAGE_ICON,
                    0,
                    0,
                    win32con.LR_LOADFROMFILE,
                )
            except Exception:
                pass
            wc.lpfnWndProc = message_map
            wc.lpszClassName = className
            win32gui.RegisterClass(wc)
            style = win32con.WS_OVERLAPPEDWINDOW
            self.hwnd = win32gui.CreateWindow(
                className,
                "Tactical RMM",
                style,
                win32con.CW_USEDEFAULT,
                win32con.CW_USEDEFAULT,
                400,
                300,
                0,
                0,
                self.hinst,
                None,
            )

            win32gui.ShowWindow(self.hwnd, win32con.SW_SHOW)

            hDC, paintStruct = win32gui.BeginPaint(self.hwnd)
            rect = win32gui.GetClientRect(self.hwnd)
            win32gui.DrawText(
                hDC,
                f"Agent: {self.agent_status}",
                -1,
                (0, 0, 384, 201),
                win32con.DT_SINGLELINE | win32con.DT_CENTER | win32con.DT_VCENTER,
            )

            win32gui.DrawText(
                hDC,
                f"Check Runner: {self.check_status}",
                -1,
                (0, 0, 384, 241),
                win32con.DT_SINGLELINE | win32con.DT_CENTER | win32con.DT_VCENTER,
            )
            win32gui.DrawText(
                hDC,
                f"Salt Minion: {self.salt_status}",
                -1,
                (0, 0, 384, 281),
                win32con.DT_SINGLELINE | win32con.DT_CENTER | win32con.DT_VCENTER,
            )
            win32gui.DrawText(
                hDC,
                f"Mesh Agent: {self.mesh_status}",
                -1,
                (0, 0, 384, 321),
                win32con.DT_SINGLELINE | win32con.DT_CENTER | win32con.DT_VCENTER,
            )

            win32gui.EndPaint(self.hwnd, paintStruct)
            win32gui.UpdateWindow(self.hwnd)

        def OnDestroy(self, hwnd, message, wparam, lparam):
            win32gui.PostQuitMessage(0)
            return True

    try:
        agent_status = psutil.win_service_get("tacticalagent").status()
    except psutil.NoSuchProcess:
        agent_status = "Not Installed"

    try:
        salt_status = psutil.win_service_get("salt-minion").status()
    except psutil.NoSuchProcess:
        salt_status = "Not Installed"

    try:
        check_status = psutil.win_service_get("checkrunner").status()
    except psutil.NoSuchProcess:
        check_status = "Not Installed"

    try:
        mesh_status = psutil.win_service_get("Mesh Agent").status()
    except psutil.NoSuchProcess:
        mesh_status = "Not Installed"

    if gui:
        win32gui.ShowWindow(window, win32con.SW_HIDE)
        w = AgentStatus(agent_status, salt_status, check_status, mesh_status)
        win32gui.PumpMessages()
        win32gui.CloseWindow(window)
    else:
        print("Agent: ", agent_status)
        print("Check Runner: ", check_status)
        print("Salt Minion: ", salt_status)
        print("Mesh Agent: ", mesh_status)
