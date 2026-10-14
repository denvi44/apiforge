from __future__ import annotations

import secrets

import flet as ft

from ...generator import iter_routes
from ...model import validate
from ..theme import issues_banner, page_header, section


class ProjectView:
    def __init__(self, app):
        self.app = app
        self.control = ft.Column(scroll=ft.ScrollMode.AUTO, expand=True, spacing=16)
        self.issues = ft.Container()
        self.stats = ft.Row(spacing=12, wrap=True)

    # liaison TextField → attribut du projet
    def _bind(self, attr: str, cast=str):
        def handler(e: ft.ControlEvent):
            try:
                setattr(self.app.project, attr, cast(e.control.value))
                e.control.error_text = None
            except ValueError:
                e.control.error_text = "Valeur invalide"
            e.control.update()
            self.app.changed()
            self._refresh_dynamic()
        return handler

    def refresh(self) -> None:
        p = self.app.project
        self.key_field = ft.TextField(
            label="Clé API (en-tête X-API-Key)", value=p.api_key, password=True, can_reveal_password=True,
            disabled=not p.api_key_enabled, expand=True, on_change=self._bind("api_key"),
            helper_text="Pour le serveur intégré uniquement : jamais écrite dans le code (variable API_KEYS).",
        )

        def toggle_key(e):
            p.api_key_enabled = e.control.value
            if p.api_key_enabled and not p.api_key:
                p.api_key = secrets.token_urlsafe(32)
                self.key_field.value = p.api_key
            self.key_field.disabled = not p.api_key_enabled
            self.key_field.update()
            self.app.changed()
            self._refresh_dynamic()

        def regenerate(_):
            p.api_key = self.key_field.value = secrets.token_urlsafe(32)
            self.key_field.update()
            self.app.changed()

        def toggle_cors(e):
            p.cors = e.control.value
            self.cors_field.disabled = not p.cors
            self.cors_field.update()
            self.app.changed()
            self._refresh_dynamic()

        def toggle_docs(e):
            p.docs_enabled = e.control.value
            self.app.changed()

        def toggle_flag(attr):
            def handler(e):
                setattr(p, attr, e.control.value)
                if attr == "users_enabled":
                    self.registration_switch.disabled = self.ttl_field.disabled = not p.users_enabled
                    self.registration_switch.update()
                    self.ttl_field.update()
                self.app.changed()
                self._refresh_dynamic()
            return handler

        self.registration_switch = ft.Switch(label="Inscription libre (POST /auth/register)",
                                             value=p.open_registration, disabled=not p.users_enabled,
                                             on_change=toggle_flag("open_registration"))
        self.ttl_field = ft.TextField(label="Validité des jetons (minutes)", value=str(p.jwt_ttl_minutes), width=240,
                                      input_filter=ft.NumbersOnlyInputFilter(), disabled=not p.users_enabled,
                                      on_change=self._bind("jwt_ttl_minutes", int), prefix_icon=ft.Icons.TIMER_OUTLINED)

        self.cors_field = ft.TextField(
            label="Origines autorisées", value=p.cors_origins, disabled=not p.cors,
            on_change=self._bind("cors_origins"), hint_text="https://app.exemple.fr, https://admin.exemple.fr",
            helper_text="Séparées par des virgules. « * » accepte toutes les origines (déconseillé en production).",
        )

        def copy_key(_):
            self.app.page.set_clipboard(p.api_key)
            self.app.toast("Clé copiée dans le presse-papiers")

        self.control.controls = [
            page_header("Projet", "Métadonnées, port d'exécution et sécurité de l'API générée."),
            self.issues,
            self.stats,
            ft.ResponsiveRow(
                [
                    ft.Container(col={"md": 12, "lg": 7}, content=section(
                        "Informations", ft.Icons.INFO_OUTLINE,
                        ft.TextField(label="Nom de l'API", value=p.name, on_change=self._bind("name"),
                                     prefix_icon=ft.Icons.BADGE_OUTLINED),
                        ft.Row([
                            ft.TextField(label="Version", value=p.version, on_change=self._bind("version"),
                                         expand=True, prefix_icon=ft.Icons.NUMBERS),
                            ft.TextField(label="Port local", value=str(p.port), on_change=self._bind("port", int),
                                         input_filter=ft.NumbersOnlyInputFilter(), width=160,
                                         prefix_icon=ft.Icons.LAN_OUTLINED),
                        ]),
                        ft.TextField(label="Description (affichée dans Swagger)", value=p.description,
                                     multiline=True, min_lines=3, max_lines=6, on_change=self._bind("description")),
                    )),
                    ft.Container(col={"md": 12, "lg": 5}, content=section(
                        "Sécurité & accès", ft.Icons.SHIELD_OUTLINED,
                        ft.Switch(label="Activer CORS", value=p.cors, on_change=toggle_cors),
                        self.cors_field,
                        ft.Switch(label="Protéger les routes par clé API", value=p.api_key_enabled,
                                  on_change=toggle_key),
                        ft.Row([
                            self.key_field,
                            ft.IconButton(ft.Icons.AUTORENEW, tooltip="Générer une nouvelle clé", on_click=regenerate),
                            ft.IconButton(ft.Icons.CONTENT_COPY, tooltip="Copier", on_click=copy_key),
                        ], vertical_alignment=ft.CrossAxisAlignment.START),
                        ft.Text("Accès service (droits admin). /health et la documentation restent publiques.",
                                size=12, color=ft.Colors.ON_SURFACE_VARIANT),
                    )),
                    ft.Container(col={"md": 12, "lg": 6}, content=section(
                        "Comptes utilisateurs", ft.Icons.PEOPLE_OUTLINE,
                        ft.Switch(label="Activer les comptes (JWT)", value=p.users_enabled,
                                  on_change=toggle_flag("users_enabled")),
                        self.registration_switch,
                        self.ttl_field,
                        ft.Text("Mots de passe scrypt, jetons révocables. Le mode d'accès de chaque ressource "
                                "(privé, partagé, lecture seule, public) se règle dans l'onglet Ressources. "
                                "Les clés API, si activées, donnent les droits administrateur.",
                                size=12, color=ft.Colors.ON_SURFACE_VARIANT),
                    )),
                    ft.Container(col={"md": 12, "lg": 6}, content=section(
                        "Protection", ft.Icons.GPP_GOOD_OUTLINED,
                        ft.Row([
                            ft.TextField(label="Requêtes / minute / IP", value=str(p.rate_limit), width=220,
                                         input_filter=ft.NumbersOnlyInputFilter(), helper_text="0 = illimité",
                                         on_change=self._bind("rate_limit", int), prefix_icon=ft.Icons.SPEED),
                            ft.TextField(label="Taille max. du corps (Ko)", value=str(p.max_body_kb), width=220,
                                         input_filter=ft.NumbersOnlyInputFilter(), helper_text="Au-delà : 413",
                                         on_change=self._bind("max_body_kb", int), prefix_icon=ft.Icons.DATA_USAGE),
                            ft.Switch(label="Documentation Swagger / ReDoc", value=p.docs_enabled,
                                      on_change=toggle_docs),
                        ], wrap=True, spacing=16, vertical_alignment=ft.CrossAxisAlignment.START),
                        ft.Text("Défauts du code généré, surchargeables par l'environnement. La limite de débit est "
                                "partagée entre workers (SQLite) ou entre machines (RATE_LIMIT_BACKEND=redis).",
                                size=12, color=ft.Colors.ON_SURFACE_VARIANT),
                    )),
                ],
                spacing=16,
                run_spacing=16,
            ),
        ]
        self._refresh_dynamic(update=False)

    def _refresh_dynamic(self, update: bool = True) -> None:
        p = self.app.project
        self.issues.content = issues_banner([i.message for i in validate(p) if i.where == "project"])
        routes = iter_routes(p)
        stats = [
            (ft.Icons.TABLE_CHART_OUTLINED, len(p.resources), "ressources"),
            (ft.Icons.VIEW_COLUMN_OUTLINED, sum(len(r.fields) for r in p.resources), "champs"),
            (ft.Icons.ALT_ROUTE, len(routes), "routes"),
            (ft.Icons.LOCK_OUTLINE if (p.api_key_enabled or p.users_enabled) else ft.Icons.LOCK_OPEN, None,
             " + ".join(x for x, on in (("comptes JWT", p.users_enabled), ("clé API", p.api_key_enabled)) if on)
             or "accès libre"),
        ]
        self.stats.controls = [
            ft.Container(
                bgcolor=ft.Colors.SECONDARY_CONTAINER, border_radius=16, padding=ft.padding.symmetric(horizontal=16, vertical=12),
                content=ft.Row([
                    ft.Icon(icon, color=ft.Colors.ON_SECONDARY_CONTAINER),
                    ft.Text(f"{value} {label}" if value is not None else label,
                            color=ft.Colors.ON_SECONDARY_CONTAINER, weight=ft.FontWeight.W_500),
                ], tight=True),
            )
            for icon, value, label in stats
        ]
        if update:
            self.issues.update()
            self.stats.update()
