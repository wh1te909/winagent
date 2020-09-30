import os
import subprocess
import sys
from time import sleep

import psutil

from agent import WindowsAgent
from utils import kill_proc, remove_dir


class MeshAgent(WindowsAgent):
    def __init__(self, log_level, log_to):
        super().__init__(log_level, log_to)
        self.mesh_svc = "mesh agent"
        self.pf = os.environ["ProgramFiles"]

    @property
    def mesh_dir(self):
        dir1 = os.path.join(self.pf, "Mesh Agent")
        dir2 = os.path.join(self.pf, "mesh\\Mesh Agent")
        if os.path.exists(dir1):
            return dir1
        elif os.path.exists(dir2):
            return dir2
        else:
            return None

    def remove_mesh(self, exe):
        print("Found existing Mesh Agent. Removing...", flush=True)
        try:
            subprocess.run(
                ["sc", "stop", self.mesh_svc], capture_output=True, timeout=30
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

        for proc in mesh_procs:
            mesh_pids.append(proc["pid"])

        for pid in mesh_pids:
            kill_proc(pid)

        try:
            r = subprocess.run([exe, "-fulluninstall"], capture_output=True, timeout=60)
        except Exception as e:
            self.logger.error(e)
            sys.stdout.flush()

        if self.mesh_dir:
            remove_dir(self.mesh_dir)

    def install_mesh(self, exe, cmd_timeout):
        attempts = 0
        retries = 5

        print("Installing mesh agent", flush=True)
        try:
            ret = subprocess.run(
                [exe, "-fullinstall"], capture_output=True, timeout=cmd_timeout
            )
        except Exception as e:
            self.logger.error(e)
            sys.stdout.flush()
            return "error"

        sleep(15)
        while 1:
            try:
                r = subprocess.run([exe, "-nodeidhex"], capture_output=True, timeout=30)
                mesh_node_id = r.stdout.decode("utf-8", errors="ignore").strip()
            except Exception as e:
                attempts += 1
                self.logger.error(e)
                self.logger.error(
                    f"Failed to get mesh node id: attempt {attempts} of {retries}"
                )
                sys.stdout.flush()
                sleep(5)
            else:
                if "not defined" in mesh_node_id.lower():
                    attempts += 1
                    self.logger.error(
                        f"Failed to get mesh node id: attempt {attempts} of {retries}"
                    )
                    sys.stdout.flush()
                    sleep(5)
                else:
                    attempts = 0

            if attempts == 0:
                break
            elif attempts >= retries:
                mesh_node_id = "error"
                break

        return mesh_node_id
