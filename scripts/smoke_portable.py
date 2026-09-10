"""Smoke-test the actual launcher using isolated data; never connect to a host."""
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
from urllib.request import Request, urlopen


def main():
    executable = Path(sys.argv[1]).resolve()
    command = [sys.executable, str(executable)] if executable.suffix == ".py" else [str(executable)]
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base = f"http://127.0.0.1:{port}"

    def request(path, data=None, method=None):
        req = Request(base + path, data=json.dumps(data).encode() if data is not None else None,
                      headers={"Content-Type": "application/json"}, method=method)
        with urlopen(req, timeout=10) as response:
            body = response.read()
            return json.loads(body) if "application/json" in response.headers.get("Content-Type", "") else body

    with tempfile.TemporaryDirectory(prefix="pangea-smoke-") as tmp:
        env = dict(os.environ, PANGEA_DATA_DIR=str(Path(tmp) / "data"))
        scenario_id = None
        for round_index in range(2):
            with open(Path(tmp) / f"run-{round_index}.log", "wb") as log:
                process = subprocess.Popen(command + ["--no-browser", "--port", str(port)], env=env, cwd=tmp, stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 60
                    while True:
                        if process.poll() is not None:
                            raise RuntimeError("Launcher exited before ready")
                        try:
                            assert request("/api/v1/health")["status"] == "ok"
                            break
                        except OSError:
                            if time.monotonic() > deadline:
                                raise
                            time.sleep(0.25)
                    html = request("/").decode()
                    assert 'id="root"' in html
                    assets = re.findall(r'(?:src|href)="(/assets/[^\"]+)"', html)
                    assert assets
                    for asset in assets:
                        assert request(asset)
                    if round_index == 0:
                        scenario = request("/api/v1/scenarios")["items"][0]
                        scenario_id = scenario["id"]
                        scenario["name"] = "Portable persistence smoke"
                        request(f"/api/v1/scenarios/{scenario_id}", scenario, "PUT")
                        preview = request("/api/v1/templates/preview", {"packet": scenario["packets"][0]})
                        assert preview["length"] > 0 and preview["hex"]
                        for kind in ("pcap", "scapy"):
                            export = request(f"/api/v1/exports/{kind}", {"scenarioId": scenario_id})
                            assert request(export["downloadUrl"])
                        sample = request('/api/v1/samples/edit', {'packet':scenario['packets'][0]})
                        template = request('/api/v1/templates', {'name':'Portable sample','packet':sample['packet']})
                        assert template['packet']['rawHex'] == sample['packet']['rawHex']
                        scenario.update(mode='listen',listenConfig={'match':{'mode':'vxlan_inner_five_tuple'},'direction':{'derive':'reverse_direction','addresses':'reverse_direction','checksums':'repair'}})
                        request(f'/api/v1/scenarios/{scenario_id}',scenario,'PUT')
                        listener = request('/api/v1/exports/scapy',{'scenarioId':scenario_id})
                        assert b'def inject(' in request(listener['downloadUrl'])
                        # A second instance on the same port must fail without taking over.
                        duplicate = subprocess.run(command + ["--no-browser", "--port", str(port)], env=env, cwd=tmp, stdout=log, stderr=log, timeout=30)
                        assert duplicate.returncode != 0
                    else:
                        assert request(f"/api/v1/scenarios/{scenario_id}")["name"] == "Portable persistence smoke"
                    assert request("/api/v1/executions")["total"] == 0
                except Exception:
                    log.flush()
                    print((Path(tmp) / f"run-{round_index}.log").read_text(errors="replace"))
                    raise
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
        print("PASS: launcher, UI assets, API, preview, exports, port conflict, restart persistence; no executions")


if __name__ == "__main__":
    main()
