from __future__ import annotations

import flet as ft

from ...generator import GenerationError, generate_files
from ..theme import code_view, issues_banner, page_header

ICONS = {
    "main.py": ft.Icons.CODE,
    "requirements.txt": ft.Icons.LIST_ALT,
    "Dockerfile": ft.Icons.DIRECTIONS_BOAT_OUTLINED,
    "README.md": ft.Icons.DESCRIPTION_OUTLINED,
    ".env.example": ft.Icons.KEY_OUTLINED,
}


class CodeView:
    """Aperçu en lecture seule des fichiers générés, avec copie et export."""

    def __init__(self, app):
        self.app = app
        self.files: dict[str, str] = {}
        self.tabs = ft.Tabs(expand=True, animation_duration=150)
        self.body = ft.Container(expand=True)
        self.control = ft.Column(
            [
                page_header(
                    "Code généré",
                    "Projet FastAPI autonome : SQLite, validation Pydantic, OpenAPI, Docker.",
                    [
                        ft.OutlinedButton("Copier le fichier", icon=ft.Icons.CONTENT_COPY, on_click=self._copy),
                        ft.FilledButton("Exporter", icon=ft.Icons.DRIVE_FILE_MOVE_OUTLINE,
                                        on_click=lambda _: self.app.export()),
                    ],
                ),
                self.body,
            ],
            expand=True,
            spacing=16,
        )

    def refresh(self) -> None:
        try:
            self.files = generate_files(self.app.project)
        except GenerationError as exc:
            self.files = {}
            self.body.content = ft.Column([
                issues_banner([i.message for i in exc.issues]),
                ft.Text("Corrige ces points dans les onglets Projet, Ressources ou Endpoints pour générer le code.",
                        color=ft.Colors.ON_SURFACE_VARIANT),
            ], spacing=12)
            return
        selected = min(self.tabs.selected_index or 0, len(self.files) - 1)
        self.tabs.tabs = [
            ft.Tab(
                text=name,
                icon=ICONS.get(name, ft.Icons.INSERT_DRIVE_FILE_OUTLINED),
                content=ft.Container(
                    code_view(content, "python" if name.endswith(".py") else "text"),
                    padding=ft.padding.only(top=12),
                ),
            )
            for name, content in self.files.items()
        ]
        self.tabs.selected_index = selected
        lines = self.files["main.py"].count("\n")
        self.body.content = ft.Column(
            [ft.Text(f"main.py : {lines} lignes", size=12, color=ft.Colors.ON_SURFACE_VARIANT), self.tabs],
            expand=True,
            spacing=4,
        )

    def _copy(self, _=None) -> None:
        if not self.files:
            self.app.toast("Rien à copier : le projet contient des erreurs.", error=True)
            return
        name = list(self.files)[self.tabs.selected_index or 0]
        self.app.page.set_clipboard(self.files[name])
        self.app.toast(f"{name} copié dans le presse-papiers")
