import argparse
import os


def main():

    parser = argparse.ArgumentParser(description="Tactical RMM Agent")
    parser.add_argument("-m", action="store", dest="mode", type=str)
    parser.add_argument("-p", action="store", dest="taskpk", type=int)
    parser.add_argument("--api", action="store", dest="api_url", type=str)
    parser.add_argument("--client-id", action="store", dest="client_id", type=int)
    parser.add_argument("--site-id", action="store", dest="site_id", type=int)
    parser.add_argument(
        "--desc", action="store", dest="agent_desc", type=str, default="changeme"
    )
    parser.add_argument(
        "--agent-type",
        action="store",
        dest="agent_type",
        type=str,
        default="server",
        choices=["server", "workstation"],
    )
    parser.add_argument("--auth", action="store", dest="auth_token", type=str)
    args = parser.parse_args()

    if args.mode == "install":
        import sys
        import threading

        if len(sys.argv) != 15:
            parser.print_help()
            raise SystemExit()

        from installer import Installer

        installer = Installer(
            api_url=args.api_url,
            client_id=args.client_id,
            site_id=args.site_id,
            agent_desc=args.agent_desc,
            agent_type=args.agent_type,
            auth_token=args.auth_token,
        )

        t = threading.Thread(target=installer.install, daemon=True)
        t.start()
        t.join()

    elif args.mode == "winagentsvc":
        from winagentsvc import WinAgentSvc

        agent = WinAgentSvc()
        agent.run()

    elif args.mode == "checkrunner":
        from checkrunner import CheckRunner

        agent = CheckRunner()
        agent.run_forever()

    elif args.mode == "runchecks":
        from checkrunner import CheckRunner

        agent = CheckRunner()
        agent.run()

    elif args.mode == "winupdater":
        from winupdater import WinUpdater

        agent = WinUpdater()
        agent.install_all()

    elif args.mode == "patchscan":
        from winupdater import WinUpdater

        agent = WinUpdater()
        agent.trigger_patch_scan()

    elif args.mode == "taskrunner":
        from taskrunner import TaskRunner

        agent = TaskRunner(task_pk=args.taskpk)
        agent.run()

    elif args.mode == "updatesalt":
        from agent import WindowsAgent

        agent = WindowsAgent()
        agent.fix_salt(by_time=False)
        agent.update_salt()

    elif args.mode == "fixsalt":
        from agent import WindowsAgent

        agent = WindowsAgent()
        agent.fix_salt()

    elif args.mode == "fixmesh":
        from agent import WindowsAgent

        agent = WindowsAgent()
        agent.fix_mesh()

    elif args.mode == "cleanup":
        from agent import WindowsAgent

        agent = WindowsAgent()
        agent.fix_salt(by_time=False)
        agent.cleanup()

    elif args.mode == "recoversalt":
        from agent import WindowsAgent

        agent = WindowsAgent()
        agent.recover_salt()

    elif args.mode == "recovermesh":
        from agent import WindowsAgent

        agent = WindowsAgent()
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
