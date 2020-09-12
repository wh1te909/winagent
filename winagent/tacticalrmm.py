import argparse
import os
import socket
import sys


def main():

    parser = argparse.ArgumentParser(description="Tactical RMM Agent")
    parser.add_argument("-m", action="store", dest="mode", type=str)
    parser.add_argument("-p", action="store", dest="taskpk", type=int)
    parser.add_argument("--api", action="store", dest="api_url", type=str)
    parser.add_argument("--client-id", action="store", dest="client_id", type=int)
    parser.add_argument("--site-id", action="store", dest="site_id", type=int)
    parser.add_argument(
        "--desc",
        action="store",
        dest="agent_desc",
        type=str,
        default=socket.gethostname(),
    )
    parser.add_argument(
        "--agent-type",
        action="store",
        dest="agent_type",
        type=str,
        default="server",
        choices=["server", "workstation"],
    )
    parser.add_argument(
        "-l",
        "--log",
        action="store",
        dest="log_level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )
    parser.add_argument(
        "--logto",
        action="store",
        dest="log_to",
        type=str,
        default="file",
        choices=["file", "stdout"],
    )
    parser.add_argument("--auth", action="store", dest="auth_token", type=str)
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--power", action="store_true")
    parser.add_argument("--rdp", action="store_true")
    parser.add_argument("--ping", action="store_true")
    parser.add_argument(
        "--local-salt",
        action="store",
        dest="local_salt",
        type=str,
        help=r'The full path to the salt-minion executable e.g. "C:\\temp\\salt-minion-setup.exe"',
    )
    parser.add_argument(
        "--local-mesh",
        action="store",
        dest="local_mesh",
        type=str,
        help=r'The full path to the Mesh Agent executable e.g. "C:\\temp\\meshagent.exe"',
    )
    args = parser.parse_args()

    if args.version:
        try:
            with open(
                os.path.join(os.environ["ProgramFiles"], "TacticalAgent", "VERSION")
            ) as f:
                ver = f.read().strip()

            print(ver)
        except Exception as e:
            print(f"Error getting version: {e}")

    elif args.mode == "install":

        if (
            not args.api_url
            or not args.client_id
            or not args.site_id
            or not args.auth_token
        ):
            parser.print_help()
            sys.exit(1)

        if args.local_salt:
            if not os.path.exists(args.local_salt):
                parser.print_help()
                sys.stdout.flush()
                print(f"\nError: {args.local_salt} does not exist\n", flush=True)
                sys.exit(1)
            if not os.path.isfile(args.local_salt):
                parser.print_help()
                sys.stdout.flush()
                print(
                    f"\nError: {args.local_salt} must be a file, not a folder.",
                    flush=True,
                )
                print(
                    r'Make sure to use double backslashes for file paths, and double quotes e.g. "C:\\temp\\salt-minion-setup.exe"',
                    flush=True,
                )
                print("", flush=True)
                sys.exit(1)

        if args.local_mesh:
            if not os.path.exists(args.local_mesh):
                parser.print_help()
                sys.stdout.flush()
                print(f"\nError: {args.local_mesh} does not exist\n", flush=True)
                sys.exit(1)
            if not os.path.isfile(args.local_mesh):
                parser.print_help()
                sys.stdout.flush()
                print(
                    f"\nError: {args.local_mesh} must be a file, not a folder.",
                    flush=True,
                )
                print(
                    r'Make sure to use double backslashes for file paths, and double quotes e.g. "C:\\temp\\meshagent.exe"',
                    flush=True,
                )
                print("", flush=True)
                sys.exit(1)

        from installer import Installer

        installer = Installer(
            api_url=args.api_url,
            client_id=args.client_id,
            site_id=args.site_id,
            agent_desc=args.agent_desc,
            agent_type=args.agent_type,
            power=args.power,
            rdp=args.rdp,
            ping=args.ping,
            auth_token=args.auth_token,
            log_level=args.log_level,
            local_salt=args.local_salt,
            local_mesh=args.local_mesh,
        )

        installer.install()

    elif args.mode == "winagentsvc":
        from winagentsvc import WinAgentSvc

        agent = WinAgentSvc(log_level=args.log_level, log_to=args.log_to)
        agent.run()

    elif args.mode == "checkrunner":
        from checkrunner import CheckRunner

        agent = CheckRunner(log_level=args.log_level, log_to=args.log_to)
        agent.run_forever()

    elif args.mode == "runchecks":
        from checkrunner import CheckRunner

        agent = CheckRunner(log_level=args.log_level, log_to=args.log_to)
        agent.run()

    elif args.mode == "winupdater":
        from winupdater import WinUpdater

        agent = WinUpdater(log_level=args.log_level, log_to=args.log_to)
        agent.install_all()

    elif args.mode == "patchscan":
        from winupdater import WinUpdater

        agent = WinUpdater(log_level=args.log_level, log_to=args.log_to)
        agent.trigger_patch_scan()

    elif args.mode == "taskrunner":
        from taskrunner import TaskRunner

        agent = TaskRunner(
            task_pk=args.taskpk, log_level=args.log_level, log_to=args.log_to
        )
        agent.run()

    elif args.mode == "updatesalt":
        from agent import WindowsAgent

        agent = WindowsAgent(log_level=args.log_level, log_to=args.log_to)
        agent.update_salt()

    elif args.mode == "fixsalt":
        from agent import WindowsAgent

        agent = WindowsAgent(log_level=args.log_level, log_to=args.log_to)
        agent.fix_salt()

    elif args.mode == "fixmesh":
        from agent import WindowsAgent

        agent = WindowsAgent(log_level=args.log_level, log_to=args.log_to)
        agent.fix_mesh()

    elif args.mode == "cleanup":
        from agent import WindowsAgent

        agent = WindowsAgent(log_level=args.log_level, log_to=args.log_to)
        agent.fix_salt(by_time=False)
        agent.cleanup()

    elif args.mode == "recoversalt":
        from agent import WindowsAgent

        agent = WindowsAgent(log_level=args.log_level, log_to=args.log_to)
        agent.recover_salt()

    elif args.mode == "recovermesh":
        from agent import WindowsAgent

        agent = WindowsAgent(log_level=args.log_level, log_to=args.log_to)
        agent.recover_mesh()

    else:
        import win32gui

        from agent import show_agent_status

        window = win32gui.GetForegroundWindow()

        if window == 0:
            # called from cli with no interactive desktop
            show_agent_status(window=None, gui=False)
        else:
            show_agent_status(window=window, gui=True)


if __name__ == "__main__":
    main()
