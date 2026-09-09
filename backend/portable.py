"""Local-only portable entry point; closing the console stops the server."""
from __future__ import annotations

import argparse
from pathlib import Path
import socket
import sys
import threading
import time
import webbrowser

import uvicorn
from fastapi.staticfiles import StaticFiles

from app.main import app
from app.storage import APP_DATA, ensure_dirs


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--port", type=int, default=18765)
    args = parser.parse_args()
    resource_root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
    frontend = resource_root / "dist"
    if not (frontend / "index.html").is_file():
        raise RuntimeError("Frontend missing. Run npm run build before packaging.")
    ensure_dirs()
    probe = APP_DATA / ".write-check"
    probe.write_text("ok", encoding="utf-8")
    probe.unlink()
    app.mount("/", StaticFiles(directory=frontend, html=True), name="frontend")
    # Bind before opening a browser: a busy port must never open an unrelated app.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if sys.platform == "win32":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", args.port))
        sock.listen(128)
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=args.port, log_level="info"))
        if not args.no_browser:
            def open_when_ready() -> None:
                while not server.started and not server.should_exit:
                    time.sleep(0.1)
                if server.started:
                    webbrowser.open(f"http://127.0.0.1:{args.port}/")
            threading.Thread(target=open_when_ready, daemon=True).start()
        print(f"Pangea: http://127.0.0.1:{args.port}/", flush=True)
        print(f"Data: {APP_DATA}\nKeep this console open. Press Ctrl+C to stop.", flush=True)
        server.run(sockets=[sock])
    finally:
        sock.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Startup failed: {exc}", file=sys.stderr, flush=True)
        if "--no-browser" not in sys.argv and sys.stdin.isatty():
            input("Press Enter to exit...")
        sys.exit(1)
