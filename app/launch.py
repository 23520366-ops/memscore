"""Start the local demo and record startup errors for troubleshooting."""
import os
import threading
import traceback
import webbrowser
from pathlib import Path

LOG = Path(__file__).resolve().parent / "results" / "startup.txt"
HOST = "127.0.0.1"
PORT = 8000
URL = f"http://{HOST}:{PORT}"


def main(app=None):
    try:
        import uvicorn

        if os.environ.get("MEMSCOPE_ALLOW_ANY_SAMPLE") == "1":
            print("WARNING: MEMSCOPE_ALLOW_ANY_SAMPLE=1 - files outside the clean allowlist can be sent "
                  "to the guests. Use only an isolated lab VM (see docs/SAFETY.md).", flush=True)
        if app is None:
            print("Loading models and data...", flush=True)
            if __package__:
                from .server import app
            else:
                from server import app

        class DemoServer(uvicorn.Server):
            async def startup(self, sockets=None):
                await super().startup(sockets=sockets)
                if self.started:
                    try:
                        LOG.unlink(missing_ok=True)
                    except OSError:
                        print("Could not clear app/results/startup.txt.", flush=True)
                    print(f"Opening {URL}", flush=True)
                    threading.Thread(target=webbrowser.open, args=(URL,), daemon=True).start()

        process = DemoServer(uvicorn.Config(app, host=HOST, port=PORT, log_level="warning"))
        process.run()
        if not process.started:
            raise RuntimeError("Uvicorn could not start the demo.")
        return 0
    except (Exception, SystemExit):
        try:
            LOG.parent.mkdir(parents=True, exist_ok=True)
            LOG.write_text(traceback.format_exc(), encoding="utf-8")
            print("\nDemo startup failed. See app/results/startup.txt for details.\n", flush=True)
        except OSError:
            print("Could not write app/results/startup.txt.", flush=True)
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
