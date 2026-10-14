"""Exécution locale de l'API générée (uvicorn en sous-processus) + client HTTP de test."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

APP_DIR = Path(os.environ.get("APIFORGE_HOME", Path.home() / ".apiforge"))
AUTOSAVE_PATH = APP_DIR / "autosave.apiforge.json"


def port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex((host, port)) == 0


def runtime_missing() -> list[str]:
    """Paquets nécessaires pour exécuter l'API dans l'interpréteur courant."""
    import importlib.util
    return [m for m in ("fastapi", "uvicorn", "pydantic") if importlib.util.find_spec(m) is None]


class ServerRunner:
    """Pilote un process uvicorn. Les callbacks sont appelés depuis un thread de lecture."""

    def __init__(self, on_log: Callable[[str], None], on_state: Callable[[bool, int | None], None]):
        self._on_log = on_log
        self._on_state = on_state
        self._proc: subprocess.Popen | None = None
        self._lock = threading.Lock()
        self.port: int | None = None
        self.code_hash: str | None = None
        self._stopping = False

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self, code: str, port: int, project_slug: str, env: dict[str, str] | None = None,
              code_hash: str | None = None) -> None:
        with self._lock:
            if self.running:
                raise RuntimeError("Le serveur tourne déjà.")
            missing = runtime_missing()
            if missing:
                raise RuntimeError(f"Paquets manquants : {', '.join(missing)} (pip install -r requirements.txt)")
            if port_in_use(port):
                raise RuntimeError(f"Le port {port} est déjà utilisé.")

            workdir = APP_DIR / "run" / project_slug
            workdir.mkdir(parents=True, exist_ok=True)
            (workdir / "main.py").write_text(code, encoding="utf-8")

            proc_env = {**os.environ, "PYTHONUNBUFFERED": "1", "APIFORGE_DB": str(workdir / "data.db"), **(env or {})}
            self._proc = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(port),
                 "--no-server-header"],
                cwd=workdir,
                env=proc_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            self.port = port
            self.code_hash = code_hash
            self._stopping = False
            self._on_log(f"▶ uvicorn démarré (pid {self._proc.pid}) — base : {workdir / 'data.db'}")
            self._on_state(True, None)
            threading.Thread(target=self._pump, args=(self._proc,), daemon=True).start()

    def _pump(self, proc: subprocess.Popen) -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            self._on_log(line.rstrip("\n"))
        code = proc.wait()
        with self._lock:
            if self._proc is proc:
                self._proc = None
                self.code_hash = None
        self._on_log(f"■ serveur arrêté (code {code})")
        self._on_state(False, None if self._stopping else code)

    def stop(self, timeout: float = 5.0) -> None:
        proc = self._proc
        if proc is None or proc.poll() is not None:
            return
        self._stopping = True
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=timeout)


@dataclass
class HttpResult:
    status: int
    elapsed_ms: float
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: str | None = None

    @property
    def pretty_body(self) -> str:
        try:
            return json.dumps(json.loads(self.body), indent=2, ensure_ascii=False)
        except (ValueError, TypeError):
            return self.body


def http_request(method: str, url: str, body: str | None = None, headers: dict[str, str] | None = None,
                 timeout: float = 15.0) -> HttpResult:
    data = body.encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Accept": "application/json", **(headers or {})})
    if data:
        req.add_header("Content-Type", "application/json")
    local = urllib.parse.urlsplit(url).hostname in ("127.0.0.1", "localhost", "::1")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({})) if local else urllib.request.build_opener()
    t0 = time.perf_counter()
    try:
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310 — URL saisie par l'utilisateur
            raw = resp.read().decode("utf-8", errors="replace")
            return HttpResult(resp.status, (time.perf_counter() - t0) * 1000, dict(resp.headers), raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        return HttpResult(exc.code, (time.perf_counter() - t0) * 1000, dict(exc.headers or {}), raw)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        return HttpResult(0, (time.perf_counter() - t0) * 1000, error=str(reason))
