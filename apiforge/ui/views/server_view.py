from __future__ import annotations

import json
import re
import threading
import urllib.parse

import flet as ft

from ...generator import GenerationError, code_hash, generate_main, iter_routes
from ...model import HTTP_METHODS
from ...runner import http_request
from ..theme import CODE_BG, CODE_FG, MONO, method_badge, page_header, section

MAX_LOG_LINES = 1500
_PARAM = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


def _log_color(line: str) -> str:
    if "ERROR" in line or "Traceback" in line or line.startswith("■"):
        return "#F38BA8"
    if "WARNING" in line:
        return "#F9E2AF"
    if line.startswith("▶") or "startup complete" in line:
        return "#A6E3A1"
    return CODE_FG


class ServerView:
    """Lancement local (uvicorn), journaux en direct et client HTTP intégré."""

    def __init__(self, app):
        self.app = app
        self._log_lock = threading.Lock()
        self.log_list = ft.ListView(expand=True, spacing=0, auto_scroll=True, padding=12)
        self.start_btn = ft.FilledButton("Démarrer", icon=ft.Icons.PLAY_ARROW, on_click=self._start)
        self.stop_btn = ft.OutlinedButton("Arrêter", icon=ft.Icons.STOP, on_click=self._stop)
        self.restart_btn = ft.FilledTonalButton("Redémarrer", icon=ft.Icons.RESTART_ALT, on_click=self._restart)
        self.docs_btn = ft.TextButton("Swagger UI", icon=ft.Icons.OPEN_IN_NEW, on_click=lambda _: self._open("/docs"))
        self.redoc_btn = ft.TextButton("ReDoc", icon=ft.Icons.MENU_BOOK_OUTLINED, on_click=lambda _: self._open("/redoc"))
        self.stale_banner = ft.Container(visible=False)
        self.url_text = ft.Text(font_family=MONO, selectable=True)

        # client HTTP
        self.method = ft.Dropdown(value="GET", width=130, label="Méthode",
                                  options=[ft.dropdown.Option(m) for m in HTTP_METHODS])
        self.url = ft.TextField(label="URL", expand=True, text_style=ft.TextStyle(font_family=MONO),
                                on_submit=lambda _: self._send())
        self.body = ft.TextField(label="Corps JSON (optionnel)", multiline=True, min_lines=3, max_lines=8,
                                 text_style=ft.TextStyle(font_family=MONO, size=13))
        self.send_btn = ft.FilledButton("Envoyer", icon=ft.Icons.SEND, on_click=lambda _: self._send())
        self.progress = ft.ProgressRing(width=18, height=18, stroke_width=2, visible=False)
        self.response_meta = ft.Row(spacing=12)
        self.response_body = ft.Text(selectable=True, font_family=MONO, size=13, color=CODE_FG)
        self.routes_column = ft.Column(spacing=2, scroll=ft.ScrollMode.AUTO, expand=True)

        logs_panel = ft.Container(
            bgcolor=CODE_BG, border_radius=12, expand=True, content=self.log_list,
        )
        response_panel = ft.Container(
            bgcolor=CODE_BG, border_radius=12, padding=12, expand=True,
            content=ft.Column([self.response_body], scroll=ft.ScrollMode.AUTO, expand=True),
        )

        self.control = ft.Column(
            [
                page_header("Serveur & tests", "Lance l'API en local, suis les journaux et teste les routes.",
                            [self.start_btn, self.restart_btn, self.stop_btn]),
                self.stale_banner,
                ft.Row(
                    [
                        ft.Column(
                            [
                                section("Serveur", ft.Icons.DNS_OUTLINED,
                                        ft.Row([self.url_text, self.docs_btn, self.redoc_btn], wrap=True)),
                                section("Journaux", ft.Icons.TERMINAL, logs_panel, expand=True,
                                        trailing=ft.IconButton(ft.Icons.CLEAR_ALL, tooltip="Vider",
                                                               on_click=self._clear_logs)),
                            ],
                            expand=5,
                            spacing=16,
                        ),
                        ft.Column(
                            [
                                section(
                                    "Client HTTP", ft.Icons.SEND_OUTLINED,
                                    ft.Row([self.method, self.url]),
                                    self.body,
                                    ft.Row([self.send_btn, self.progress, self.response_meta],
                                           vertical_alignment=ft.CrossAxisAlignment.CENTER),
                                    response_panel,
                                    expand=3,
                                ),
                                section("Routes", ft.Icons.ALT_ROUTE, self.routes_column, expand=2),
                            ],
                            expand=6,
                            spacing=16,
                        ),
                    ],
                    expand=True,
                    spacing=16,
                    vertical_alignment=ft.CrossAxisAlignment.STRETCH,
                ),
            ],
            expand=True,
            spacing=16,
        )

    # ── Cycle de vie ─────────────────────────────────────────────────
    @property
    def base_url(self) -> str:
        port = self.app.runner.port if self.app.runner.running else self.app.project.port
        return f"http://127.0.0.1:{port}"

    def refresh(self) -> None:
        self.on_state_changed(update=False)
        self.routes_column.controls = [
            ft.Container(
                ink=True, border_radius=8, padding=ft.padding.symmetric(horizontal=8, vertical=6),
                on_click=lambda _, m=r.method, p=r.path: self._fill(m, p),
                content=ft.Row([method_badge(r.method), ft.Text(r.path, font_family=MONO, size=13, expand=True),
                                ft.Text(r.summary, size=12, color=ft.Colors.ON_SURFACE_VARIANT)]),
            )
            for r in iter_routes(self.app.project)
        ]
        if not self.url.value:
            self.url.value = self.base_url + "/health"

    def on_state_changed(self, update: bool = True) -> None:
        running = self.app.runner.running
        self.start_btn.disabled = running
        self.stop_btn.disabled = self.restart_btn.disabled = not running
        self.docs_btn.disabled = self.redoc_btn.disabled = not running
        self.url_text.value = self.base_url if running else "Arrêté"
        self.url_text.color = ft.Colors.PRIMARY if running else ft.Colors.ON_SURFACE_VARIANT
        stale = False
        if running and self.app.runner.code_hash:
            try:
                stale = code_hash(generate_main(self.app.project)) != self.app.runner.code_hash
            except GenerationError:
                stale = True
        self.stale_banner.visible = stale
        self.stale_banner.content = ft.Container(
            bgcolor=ft.Colors.TERTIARY_CONTAINER, border_radius=12, padding=12,
            content=ft.Row([
                ft.Icon(ft.Icons.SYNC_PROBLEM, color=ft.Colors.ON_TERTIARY_CONTAINER),
                ft.Text("Le projet a changé depuis le démarrage : redémarre pour appliquer les modifications.",
                        color=ft.Colors.ON_TERTIARY_CONTAINER, expand=True),
                ft.TextButton("Redémarrer", on_click=self._restart),
            ]),
        ) if stale else None
        if update and self.control.page:
            self.control.update()

    # ── Actions serveur ──────────────────────────────────────────────
    def _start(self, _=None) -> None:
        p = self.app.project
        try:
            code = generate_main(p)
        except GenerationError as exc:
            self.app.toast(f"Génération impossible : {len(exc.issues)} problème(s). Voir l'onglet Code.", error=True)
            return
        try:
            env = {"API_KEYS": p.api_key} if p.api_key_enabled else {}
            self.app.runner.start(code, int(p.port), p.slug, env=env, code_hash=code_hash(code))
        except (RuntimeError, OSError) as exc:
            self.app.toast(str(exc), error=True)
            return
        parts = urllib.parse.urlsplit(self.url.value or "")
        self.url.value = self.base_url + (parts.path or "/health") + (f"?{parts.query}" if parts.query else "")
        self.refresh()
        self.app.page.update()

    def _stop(self, _=None) -> None:
        self.app.page.run_thread(self.app.runner.stop)

    def _restart(self, _=None) -> None:
        def job():
            self.app.runner.stop()
            self._start()
        self.app.page.run_thread(job)

    def _open(self, path: str) -> None:
        self.app.page.launch_url(self.base_url + path)

    # ── Journaux (appelé depuis le thread du runner) ─────────────────
    def append_log(self, line: str) -> None:
        with self._log_lock:
            self.log_list.controls.append(
                ft.Text(line, font_family=MONO, size=12, color=_log_color(line), selectable=True))
            overflow = len(self.log_list.controls) - MAX_LOG_LINES
            if overflow > 0:
                del self.log_list.controls[:overflow]
            if self.log_list.page:
                try:
                    self.log_list.update()
                except Exception:  # vue démontée entre-temps
                    pass

    def _clear_logs(self, _=None) -> None:
        with self._log_lock:
            self.log_list.controls.clear()
            self.log_list.update()

    # ── Client HTTP ──────────────────────────────────────────────────
    def _fill(self, method: str, path: str) -> None:
        self.method.value = method
        self.url.value = self.base_url + _PARAM.sub(lambda m: "1" if m.group(1) == "item_id" else "test", path)
        if method in ("POST", "PUT", "PATCH") and not self.body.value:
            self.body.value = self._sample_body(path)
        self.control.update()

    def _sample_body(self, path: str) -> str:
        examples = {"str": "texte", "int": 1, "float": 9.99, "bool": True, "date": "2026-01-01",
                    "datetime": "2026-01-01T12:00:00"}
        for r in self.app.project.resources:
            if path.startswith(r.route_prefix):
                return json.dumps({f.name: examples[f.type] for f in r.fields}, indent=2, ensure_ascii=False)
        return ""

    def _send(self) -> None:
        body = (self.body.value or "").strip()
        if body:
            try:
                json.loads(body)
                self.body.error_text = None
            except ValueError as exc:
                self.body.error_text = f"JSON invalide : {exc}"
                self.body.update()
                return
        headers = {}
        p = self.app.project
        if p.api_key_enabled and p.api_key:
            headers["X-API-Key"] = p.api_key
        self.send_btn.disabled, self.progress.visible = True, True
        self.control.update()

        def job():
            res = http_request(self.method.value or "GET", (self.url.value or "").strip(),
                               body if self.method.value not in ("GET", "DELETE") else None, headers)
            self.send_btn.disabled, self.progress.visible = False, False
            if res.error:
                color, label = ft.Colors.ERROR, "Échec"
                self.response_body.value = f"Requête impossible : {res.error}\n\nLe serveur est-il démarré ?"
            else:
                color = (ft.Colors.GREEN_700 if res.status < 300 else
                         ft.Colors.ORANGE_800 if res.status < 500 else ft.Colors.RED_700)
                label = str(res.status)
                self.response_body.value = res.pretty_body or "(corps vide)"
            self.response_meta.controls = [
                ft.Container(ft.Text(label, color=ft.Colors.WHITE, weight=ft.FontWeight.BOLD, size=12),
                             bgcolor=color, border_radius=6, padding=ft.padding.symmetric(horizontal=8, vertical=3)),
                ft.Text(f"{res.elapsed_ms:.0f} ms", size=12, color=ft.Colors.ON_SURFACE_VARIANT),
            ]
            self.control.update()

        self.app.page.run_thread(job)
