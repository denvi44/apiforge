from __future__ import annotations

import json

import flet as ft

from ...model import HTTP_METHODS, Endpoint, parse_response, validate
from ..theme import MONO, empty_state, issues_banner, method_badge, page_header

TEMPLATES = {
    "Bienvenue": Endpoint("GET", "/hello/{name}", "Message de bienvenue", 200, '{"message": "Bonjour {name} !"}'),
    "Version": Endpoint("GET", "/version", "Version du service", 200, '{"version": "1.0.0", "build": "dev"}'),
    "Webhook": Endpoint("POST", "/webhooks/{source}", "Réception de webhook", 202,
                        '{"accepted": true, "source": "{source}"}', "webhooks"),
    "Ping vide": Endpoint("GET", "/ping", "Ping sans contenu", 204, "", "system"),
}


class EndpointsView:
    """Endpoints libres renvoyant une réponse JSON fixe (mocks, statuts, webhooks…)."""

    def __init__(self, app):
        self.app = app
        self.issues = ft.Container()
        self.list = ft.Column(spacing=12)
        menu = ft.PopupMenuButton(
            icon=ft.Icons.AUTO_AWESOME_OUTLINED,
            tooltip="Ajouter depuis un modèle",
            items=[ft.PopupMenuItem(text=name, on_click=lambda _, n=name: self._add(TEMPLATES[n]))
                   for name in TEMPLATES],
        )
        self.control = ft.Column(
            [
                page_header(
                    "Endpoints personnalisés",
                    "Routes libres à réponse JSON fixe. Les {paramètres} du chemin sont injectés dans la réponse.",
                    [menu, ft.FilledButton("Nouvel endpoint", icon=ft.Icons.ADD, on_click=lambda _: self._add())],
                ),
                self.issues,
                ft.Column([self.list], scroll=ft.ScrollMode.AUTO, expand=True),
            ],
            expand=True,
            spacing=16,
        )

    def refresh(self) -> None:
        eps = self.app.project.endpoints
        self._render_issues(update=False)
        if not eps:
            self.list.controls = [ft.Container(height=360, content=empty_state(
                ft.Icons.ALT_ROUTE, "Aucun endpoint personnalisé",
                "Idéal pour des mocks, un /version ou un récepteur de webhook.",
                ft.FilledTonalButton("Ajouter un endpoint", icon=ft.Icons.ADD, on_click=lambda _: self._add()),
            ))]
        else:
            self.list.controls = [self._card(i, e) for i, e in enumerate(eps)]

    def _render_issues(self, update: bool = True) -> None:
        msgs = [i.message for i in validate(self.app.project) if i.where.startswith("endpoint:")]
        self.issues.content = issues_banner(msgs)
        if update:
            self.issues.update()

    def _add(self, template: Endpoint | None = None) -> None:
        e = Endpoint(**vars(template)) if template else Endpoint(path="/nouveau", summary="", response='{"ok": true}')
        existing = {(x.method, x.path) for x in self.app.project.endpoints}
        base, n = e.path, 2
        while (e.method, e.path) in existing:
            e.path = f"{base}-{n}"
            n += 1
        self.app.project.endpoints.append(e)
        self.app.changed()
        self.refresh()
        self.app.page.update()

    def _card(self, index: int, e: Endpoint) -> ft.Control:
        badge_slot = ft.Container(method_badge(e.method))
        params_text = ft.Text(self._params_label(e), size=12, color=ft.Colors.ON_SURFACE_VARIANT)
        response_field = ft.TextField(
            label="Réponse JSON", value=e.response, multiline=True, min_lines=3, max_lines=12,
            text_style=ft.TextStyle(font_family=MONO, size=13), disabled=e.status_code == 204,
            helper_text="Ignorée pour le code 204." if e.status_code == 204 else None,
        )

        def changed():
            self.app.changed()
            self._render_issues()

        def on_method(ev):
            e.method = ev.control.value
            badge_slot.content = method_badge(e.method)
            badge_slot.update()
            changed()

        def on_path(ev):
            e.path = (ev.control.value or "").strip()
            params_text.value = self._params_label(e)
            params_text.update()
            changed()

        def on_status(ev):
            try:
                e.status_code = int(ev.control.value)
            except (TypeError, ValueError):
                return
            response_field.disabled = e.status_code == 204
            response_field.helper_text = "Ignorée pour le code 204." if e.status_code == 204 else None
            response_field.update()
            changed()

        def on_text(attr):
            def handler(ev):
                setattr(e, attr, ev.control.value or "")
                changed()
            return handler

        def on_response(ev):
            e.response = ev.control.value or ""
            try:
                parse_response(e.response)
                response_field.error_text = None
            except ValueError as exc:
                response_field.error_text = f"JSON invalide : {exc}"
            response_field.update()
            changed()

        def prettify(_):
            try:
                e.response = response_field.value = json.dumps(parse_response(e.response), indent=2,
                                                               ensure_ascii=False)
                response_field.error_text = None
                response_field.update()
                changed()
            except ValueError:
                self.app.toast("Impossible de formater : JSON invalide.", error=True)

        def delete(_):
            self.app.project.endpoints.pop(index)
            changed()
            self.refresh()
            self.app.page.update()

        def duplicate(_):
            self._add(Endpoint(**vars(e)))

        response_field.on_change = on_response
        return ft.Card(
            elevation=1,
            content=ft.Container(
                padding=20,
                content=ft.Column(
                    [
                        ft.Row(
                            [
                                badge_slot,
                                ft.Dropdown(value=e.method, width=130, label="Méthode",
                                            options=[ft.dropdown.Option(m) for m in HTTP_METHODS],
                                            on_change=on_method),
                                ft.TextField(label="Chemin", value=e.path, expand=True, on_change=on_path,
                                             text_style=ft.TextStyle(font_family=MONO)),
                                ft.TextField(label="Code HTTP", value=str(e.status_code), width=110,
                                             input_filter=ft.NumbersOnlyInputFilter(), on_change=on_status),
                                ft.IconButton(ft.Icons.CONTENT_COPY_OUTLINED, tooltip="Dupliquer", on_click=duplicate),
                                ft.IconButton(ft.Icons.DELETE_OUTLINE, icon_color=ft.Colors.ERROR,
                                              tooltip="Supprimer", on_click=delete),
                            ],
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        ),
                        ft.Row([
                            ft.TextField(label="Résumé (Swagger)", value=e.summary, expand=3,
                                         on_change=on_text("summary")),
                            ft.TextField(label="Tag", value=e.tag, expand=1, on_change=on_text("tag")),
                        ]),
                        response_field,
                        ft.Row([params_text, ft.Container(expand=True),
                                ft.TextButton("Formater le JSON", icon=ft.Icons.DATA_OBJECT, on_click=prettify)]),
                    ],
                    spacing=12,
                ),
            ),
        )

    @staticmethod
    def _params_label(e: Endpoint) -> str:
        params = e.path_params
        if not params:
            return "Aucun paramètre de chemin."
        return "Paramètres utilisables dans la réponse : " + ", ".join("{" + p + "}" for p in params)
