"""Fenêtre principale : AppBar, rail de navigation, dialogues, fichiers, état serveur."""
from __future__ import annotations

import atexit
import logging
from pathlib import Path
from typing import Callable

import flet as ft

from ..generator import GenerationError, export_project
from ..model import Project
from ..runner import AUTOSAVE_PATH, ServerRunner
from .theme import SEED_COLOR
from .views.code_view import CodeView
from .views.endpoints_view import EndpointsView
from .views.project_view import ProjectView
from .views.resources_view import ResourcesView
from .views.server_view import ServerView

log = logging.getLogger("apiforge")

NAV = [
    (ft.Icons.TUNE_OUTLINED, ft.Icons.TUNE, "Projet"),
    (ft.Icons.TABLE_CHART_OUTLINED, ft.Icons.TABLE_CHART, "Ressources"),
    (ft.Icons.ALT_ROUTE_OUTLINED, ft.Icons.ALT_ROUTE, "Endpoints"),
    (ft.Icons.CODE_OUTLINED, ft.Icons.CODE, "Code"),
    (ft.Icons.PLAY_CIRCLE_OUTLINE, ft.Icons.PLAY_CIRCLE, "Serveur"),
]


class ApiForgeApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.project = self._load_autosave()
        self.file_path: Path | None = None
        self.runner = ServerRunner(on_log=self._on_server_log, on_state=self._on_server_state)
        atexit.register(self.runner.stop)

        self._configure_page()
        self._build_file_pickers()

        self.project_view = ProjectView(self)
        self.resources_view = ResourcesView(self)
        self.endpoints_view = EndpointsView(self)
        self.code_view = CodeView(self)
        self.server_view = ServerView(self)
        self.views = [self.project_view, self.resources_view, self.endpoints_view, self.code_view, self.server_view]

        self.status_chip = ft.Container(border_radius=16, padding=ft.padding.symmetric(horizontal=12, vertical=6))
        self._build_appbar()
        self.rail = ft.NavigationRail(
            selected_index=0,
            label_type=ft.NavigationRailLabelType.ALL,
            min_width=96,
            group_alignment=-0.9,
            destinations=[ft.NavigationRailDestination(icon=i, selected_icon=s, label=l) for i, s, l in NAV],
            on_change=lambda e: self.navigate(e.control.selected_index),
        )
        self.body = ft.Container(expand=True, padding=ft.padding.only(left=24, right=24, top=16, bottom=16))
        page.add(ft.Row([self.rail, ft.VerticalDivider(width=1), self.body], expand=True, spacing=0))
        self._refresh_status_chip()
        self.navigate(0)

    # ── Configuration ────────────────────────────────────────────────
    def _configure_page(self) -> None:
        p = self.page
        p.title = "APIForge — Générateur d'API"
        p.theme = ft.Theme(color_scheme_seed=SEED_COLOR, use_material3=True)
        p.dark_theme = ft.Theme(color_scheme_seed=SEED_COLOR, use_material3=True)
        p.theme_mode = ft.ThemeMode.SYSTEM
        p.padding = 0
        p.window.width, p.window.height = 1320, 860
        p.window.min_width, p.window.min_height = 1000, 680
        p.window.prevent_close = True
        p.window.on_event = self._on_window_event
        p.on_keyboard_event = self._on_key

    def _build_appbar(self) -> None:
        self.theme_btn = ft.IconButton(ft.Icons.DARK_MODE_OUTLINED, tooltip="Thème clair / sombre",
                                       on_click=self._toggle_theme)
        self.page.appbar = ft.AppBar(
            leading=ft.Icon(ft.Icons.API_ROUNDED, color=ft.Colors.PRIMARY, size=28),
            leading_width=56,
            title=ft.Text("APIForge", weight=ft.FontWeight.W_700),
            center_title=False,
            bgcolor=ft.Colors.SURFACE_CONTAINER,
            actions=[
                self.status_chip,
                ft.Container(width=12),
                ft.IconButton(ft.Icons.NOTE_ADD_OUTLINED, tooltip="Nouveau projet", on_click=self._new_project),
                ft.IconButton(ft.Icons.FOLDER_OPEN_OUTLINED, tooltip="Ouvrir… (Ctrl+O)",
                              on_click=lambda _: self.open_picker.pick_files(
                                  dialog_title="Ouvrir un projet APIForge", allowed_extensions=["json"])),
                ft.IconButton(ft.Icons.SAVE_OUTLINED, tooltip="Enregistrer (Ctrl+S)", on_click=lambda _: self.save()),
                ft.IconButton(ft.Icons.DRIVE_FILE_MOVE_OUTLINE, tooltip="Exporter le projet FastAPI (Ctrl+E)",
                              on_click=lambda _: self.export()),
                self.theme_btn,
                ft.Container(width=8),
            ],
        )

    def _build_file_pickers(self) -> None:
        self.open_picker = ft.FilePicker(on_result=self._on_open_result)
        self.save_picker = ft.FilePicker(on_result=self._on_save_result)
        self.export_picker = ft.FilePicker(on_result=self._on_export_result)
        self.page.overlay.extend([self.open_picker, self.save_picker, self.export_picker])

    # ── Navigation & état ────────────────────────────────────────────
    def navigate(self, index: int) -> None:
        self.rail.selected_index = index
        view = self.views[index]
        view.refresh()
        self.body.content = view.control
        self.page.update()

    def current_view(self):
        return self.views[self.rail.selected_index or 0]

    def changed(self) -> None:
        """À appeler après toute modification du projet."""
        try:
            self.project.save(AUTOSAVE_PATH)
        except OSError:
            log.exception("autosave impossible")

    def replace_project(self, project: Project, path: Path | None = None) -> None:
        self.project = project
        self.file_path = path
        self.resources_view.selected = 0 if project.resources else None
        self.changed()
        self.navigate(self.rail.selected_index or 0)

    @staticmethod
    def _load_autosave() -> Project:
        try:
            if AUTOSAVE_PATH.exists():
                return Project.load(AUTOSAVE_PATH)
        except (OSError, ValueError, TypeError, KeyError):
            log.exception("autosave illisible, projet d'exemple chargé")
        return Project.sample()

    # ── Fichiers ─────────────────────────────────────────────────────
    def save(self) -> None:
        if self.file_path:
            self._write_project(self.file_path)
        else:
            self.save_picker.save_file(dialog_title="Enregistrer le projet",
                                       file_name=f"{self.project.slug}.apiforge.json", allowed_extensions=["json"])

    def export(self) -> None:
        try:
            from ..generator import generate_files
            generate_files(self.project)
        except GenerationError as exc:
            self.toast(f"Export impossible : {len(exc.issues)} problème(s). Voir l'onglet Code.", error=True)
            self.navigate(3)
            return
        self.export_picker.get_directory_path(dialog_title="Dossier de destination")

    def _write_project(self, path: Path) -> None:
        try:
            self.project.save(path)
            self.file_path = path
            self.toast(f"Projet enregistré : {path.name}")
        except OSError as exc:
            self.toast(f"Enregistrement impossible : {exc}", error=True)

    def _on_open_result(self, e: ft.FilePickerResultEvent) -> None:
        if not e.files:
            return
        path = Path(e.files[0].path)
        try:
            self.replace_project(Project.load(path), path)
            self.toast(f"Projet chargé : {path.name}")
        except (OSError, ValueError, TypeError, KeyError) as exc:
            self.toast(f"Fichier invalide : {exc}", error=True)

    def _on_save_result(self, e: ft.FilePickerResultEvent) -> None:
        if e.path:
            path = Path(e.path)
            if path.suffix != ".json":
                path = path.with_suffix(".json")
            self._write_project(path)

    def _on_export_result(self, e: ft.FilePickerResultEvent) -> None:
        if not e.path:
            return
        try:
            target = export_project(self.project, e.path)
            self.toast(f"Projet FastAPI exporté dans {target}")
        except (OSError, GenerationError) as exc:
            self.toast(f"Export impossible : {exc}", error=True)

    def _new_project(self, _=None) -> None:
        def reset(template: bool):
            self.replace_project(Project.sample() if template else Project(name="Nouvelle API"))
            self.navigate(0)

        self.dialog(
            "Nouveau projet",
            ft.Text("Le projet actuel sera remplacé (il reste enregistré s'il a été sauvegardé)."),
            [
                ft.TextButton("Annuler"),
                ft.OutlinedButton("Projet vide", on_click=lambda _: reset(False)),
                ft.FilledButton("Depuis l'exemple", on_click=lambda _: reset(True)),
            ],
        )

    # ── Serveur ──────────────────────────────────────────────────────
    def _on_server_log(self, line: str) -> None:
        self.server_view.append_log(line)

    def _on_server_state(self, running: bool, exit_code: int | None) -> None:
        self._refresh_status_chip()
        self.server_view.on_state_changed()
        if not running and exit_code not in (None, 0):
            self.toast(f"Le serveur s'est arrêté avec le code {exit_code} — voir les journaux.", error=True)
        self.page.update()

    def _refresh_status_chip(self) -> None:
        on = self.runner.running
        self.status_chip.bgcolor = ft.Colors.GREEN_100 if on else ft.Colors.SURFACE_CONTAINER_HIGHEST
        self.status_chip.content = ft.Row(
            [
                ft.Icon(ft.Icons.CIRCLE, size=10, color=ft.Colors.GREEN_700 if on else ft.Colors.OUTLINE),
                ft.Text(f"En ligne · :{self.runner.port}" if on else "Serveur arrêté", size=12,
                        color=ft.Colors.GREEN_900 if on else ft.Colors.ON_SURFACE_VARIANT),
            ],
            spacing=6,
            tight=True,
        )
        self.status_chip.on_click = lambda _: self.navigate(4)

    # ── UI helpers ───────────────────────────────────────────────────
    def toast(self, message: str, error: bool = False) -> None:
        self.page.open(ft.SnackBar(
            ft.Text(message, color=ft.Colors.ON_ERROR_CONTAINER if error else None),
            bgcolor=ft.Colors.ERROR_CONTAINER if error else None,
            behavior=ft.SnackBarBehavior.FLOATING,
            show_close_icon=True,
            duration=4000 if not error else 7000,
        ))

    def dialog(self, title: str, content: ft.Control, actions: list[ft.Control]) -> ft.AlertDialog:
        dlg = ft.AlertDialog(modal=True, title=ft.Text(title), content=content,
                             actions_alignment=ft.MainAxisAlignment.END)

        def wrap(action: ft.Control) -> ft.Control:
            original: Callable | None = getattr(action, "on_click", None)

            def handler(e):
                self.page.close(dlg)
                if original:
                    original(e)
            action.on_click = handler
            return action

        dlg.actions = [wrap(a) for a in actions]
        self.page.open(dlg)
        return dlg

    def confirm(self, title: str, message: str, on_yes: Callable[[], None], danger: bool = True) -> None:
        self.dialog(title, ft.Text(message), [
            ft.TextButton("Annuler"),
            ft.FilledButton("Supprimer" if danger else "Confirmer",
                            style=ft.ButtonStyle(bgcolor=ft.Colors.ERROR, color=ft.Colors.ON_ERROR) if danger else None,
                            on_click=lambda _: on_yes()),
        ])

    def prompt(self, title: str, label: str, on_ok: Callable[[str], str | None], value: str = "",
               helper: str = "") -> None:
        """Dialogue de saisie ; `on_ok` renvoie un message d'erreur ou None si OK."""
        field = ft.TextField(label=label, value=value, helper_text=helper, autofocus=True, width=380)
        dlg = ft.AlertDialog(modal=True, title=ft.Text(title), content=field)

        def submit(_=None):
            error = on_ok((field.value or "").strip())
            if error:
                field.error_text = error
                field.update()
            else:
                self.page.close(dlg)

        field.on_submit = submit
        dlg.actions = [ft.TextButton("Annuler", on_click=lambda _: self.page.close(dlg)),
                       ft.FilledButton("Valider", on_click=submit)]
        self.page.open(dlg)

    def _toggle_theme(self, _=None) -> None:
        dark = self.page.theme_mode != ft.ThemeMode.DARK
        if self.page.theme_mode == ft.ThemeMode.SYSTEM:
            dark = self.page.platform_brightness != ft.Brightness.DARK
        self.page.theme_mode = ft.ThemeMode.DARK if dark else ft.ThemeMode.LIGHT
        self.theme_btn.icon = ft.Icons.LIGHT_MODE_OUTLINED if dark else ft.Icons.DARK_MODE_OUTLINED
        self.page.update()

    def _on_key(self, e: ft.KeyboardEvent) -> None:
        if not e.ctrl and not e.meta:
            return
        key = e.key.upper()
        if key == "S":
            self.save()
        elif key == "O":
            self.open_picker.pick_files(allowed_extensions=["json"])
        elif key == "E":
            self.export()
        elif key in "12345" and len(key) == 1:
            self.navigate(int(key) - 1)

    def _on_window_event(self, e) -> None:
        if getattr(e, "data", None) == "close":
            self.runner.stop()
            self.page.window.destroy()
