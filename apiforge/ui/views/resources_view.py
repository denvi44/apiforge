from __future__ import annotations

import flet as ft

from ...model import ACCESS_MODES, CRUD_LABELS, CRUD_OPS, FIELD_TYPE_LABELS, FIELD_TYPES, Field, Resource, _check_ident, validate
from ..theme import MONO, empty_state, issues_banner, method_badge, page_header, section


class ResourcesView:
    """Liste des ressources à gauche, éditeur (champs + opérations CRUD) à droite."""

    def __init__(self, app):
        self.app = app
        self.selected: int | None = 0 if app.project.resources else None
        self.list_view = ft.ListView(spacing=2, expand=True)
        self.editor = ft.Container(expand=True)
        self.control = ft.Column(
            [
                page_header(
                    "Ressources",
                    "Chaque ressource devient une table SQLite et un jeu de routes CRUD.",
                    [ft.FilledButton("Nouvelle ressource", icon=ft.Icons.ADD, on_click=self._add_resource)],
                ),
                ft.Row(
                    [
                        ft.Card(elevation=1, width=280, content=ft.Container(self.list_view, padding=8)),
                        self.editor,
                    ],
                    expand=True,
                    spacing=16,
                    vertical_alignment=ft.CrossAxisAlignment.STRETCH,
                ),
            ],
            expand=True,
            spacing=16,
        )

    @property
    def resources(self) -> list[Resource]:
        return self.app.project.resources

    def refresh(self) -> None:
        if not self.resources:
            self.selected = None
        elif self.selected is None or self.selected >= len(self.resources):
            self.selected = 0
        self._render_list()
        self._render_editor()

    # ── Liste ────────────────────────────────────────────────────────
    def _render_list(self, update: bool = False) -> None:
        bad = {i.where for i in validate(self.app.project)}
        self.list_view.controls = [
            ft.ListTile(
                leading=ft.Icon(ft.Icons.ERROR_OUTLINE if f"resource:{i}" in bad else ft.Icons.TABLE_CHART_OUTLINED,
                                color=ft.Colors.ERROR if f"resource:{i}" in bad else None),
                title=ft.Text(r.name or "(sans nom)", weight=ft.FontWeight.W_600, font_family=MONO),
                subtitle=ft.Text(f"{len(r.fields)} champ(s) · {r.route_prefix}", size=12),
                selected=i == self.selected,
                dense=True,
                on_click=lambda _, i=i: self._select(i),
            )
            for i, r in enumerate(self.resources)
        ] or [ft.Container(ft.Text("Aucune ressource", color=ft.Colors.ON_SURFACE_VARIANT), padding=16)]
        if update:
            self.list_view.update()

    def _select(self, index: int) -> None:
        self.selected = index
        self._render_list()
        self._render_editor()
        self.app.page.update()

    def _add_resource(self, _=None) -> None:
        def create(name: str) -> str | None:
            if err := _check_ident(name):
                return err.capitalize()
            if any(r.name == name for r in self.resources):
                return "Ce nom existe déjà"
            self.resources.append(Resource(name=name, fields=[Field("name", "str")]))
            self.selected = len(self.resources) - 1
            self.app.changed()
            self._render_list()
            self._render_editor()
            self.app.page.update()
            return None

        self.app.prompt("Nouvelle ressource", "Nom (singulier, ex. product)", create,
                        helper="Minuscules, chiffres et _ — devient le nom de table.")

    def _delete_resource(self) -> None:
        r = self.resources[self.selected]

        def do():
            self.resources.pop(self.selected)
            self.selected = min(self.selected, len(self.resources) - 1) if self.resources else None
            self.app.changed()
            self.refresh()
            self.app.page.update()

        self.app.confirm("Supprimer la ressource", f"Supprimer « {r.name} » et ses {len(r.fields)} champ(s) ?", do)

    # ── Éditeur ──────────────────────────────────────────────────────
    def _touch(self) -> None:
        """Changement mineur : sauvegarde + rafraîchit liste et bandeau d'erreurs sans reconstruire l'éditeur."""
        self.app.changed()
        self._render_list(update=True)
        self._render_issues(update=True)

    def _render_issues(self, update: bool = False) -> None:
        where = f"resource:{self.selected}"
        self.issues_box.content = issues_banner([i.message for i in validate(self.app.project) if i.where == where])
        if update:
            self.issues_box.update()

    def _render_editor(self) -> None:
        if self.selected is None:
            self.editor.content = empty_state(
                ft.Icons.TABLE_CHART_OUTLINED, "Aucune ressource",
                "Une ressource (ex. product, customer) génère sa table et ses routes CRUD.",
                ft.FilledTonalButton("Créer une ressource", icon=ft.Icons.ADD, on_click=self._add_resource),
            )
            return
        r = self.resources[self.selected]
        self.issues_box = ft.Container()
        self._render_issues()

        def set_attr(attr):
            def handler(e):
                setattr(r, attr, (e.control.value or "").strip())
                if attr in ("name", "path"):
                    self.prefix_preview.value = r.route_prefix
                    self.prefix_preview.update()
                self._touch()
            return handler

        def set_op(op):
            def handler(e):
                r.ops[op] = e.control.value
                self._touch()
                self.routes_box.content = self._routes_preview(r)
                self.routes_box.update()
            return handler

        self.prefix_preview = ft.Text(r.route_prefix, font_family=MONO, color=ft.Colors.PRIMARY)
        self.routes_box = ft.Container(self._routes_preview(r))
        self.fields_column = ft.Column(spacing=8)
        self._render_fields(r)

        self.editor.content = ft.Column(
            [
                self.issues_box,
                section(
                    "Définition", ft.Icons.EDIT_NOTE,
                    ft.Row([
                        ft.TextField(label="Nom", value=r.name, on_change=set_attr("name"), expand=1,
                                     text_style=ft.TextStyle(font_family=MONO)),
                        ft.TextField(label="Chemin (optionnel)", value=r.path, hint_text=r.route_prefix,
                                     on_change=set_attr("path"), expand=1, text_style=ft.TextStyle(font_family=MONO)),
                    ]),
                    ft.TextField(label="Description", value=r.description, on_change=set_attr("description")),
                    ft.Dropdown(
                        label="Accès", value=r.access, expand=True,
                        options=[ft.dropdown.Option(key=k, text=v) for k, v in ACCESS_MODES.items()],
                        on_change=set_attr("access"),
                    ),
                    ft.Text(self._access_hint(r), size=12, color=ft.Colors.ON_SURFACE_VARIANT),
                    ft.Row([ft.Text("Préfixe des routes :"), self.prefix_preview]),
                    trailing=ft.IconButton(ft.Icons.DELETE_OUTLINE, icon_color=ft.Colors.ERROR,
                                           tooltip="Supprimer la ressource",
                                           on_click=lambda _: self._delete_resource()),
                ),
                section(
                    "Champs", ft.Icons.VIEW_COLUMN_OUTLINED,
                    ft.Text("Un identifiant entier « id » auto-incrémenté est toujours ajouté.",
                            size=12, color=ft.Colors.ON_SURFACE_VARIANT),
                    self.fields_column,
                    ft.Row([ft.OutlinedButton("Ajouter un champ", icon=ft.Icons.ADD,
                                              on_click=lambda _: self._add_field(r))]),
                ),
                section(
                    "Opérations", ft.Icons.ALT_ROUTE,
                    ft.Row([ft.Checkbox(label=CRUD_LABELS[op], value=r.ops.get(op, True), on_change=set_op(op))
                            for op in CRUD_OPS], wrap=True),
                    self.routes_box,
                ),
            ],
            scroll=ft.ScrollMode.AUTO,
            expand=True,
            spacing=16,
        )

    def _access_hint(self, r: Resource) -> str:
        p = self.app.project
        if not (p.users_enabled or p.api_key_enabled):
            return ("Aucune authentification activée (onglet Projet) : tout appelant a tous les droits, "
                    "le mode d'accès n'a donc pas d'effet.")
        if r.access == "owner" and not p.users_enabled:
            return "Sans comptes utilisateurs, le mode privé se comporte comme « partagé »."
        return "Les clés API et les comptes admin ont toujours tous les droits."

    def _routes_preview(self, r: Resource) -> ft.Control:
        base = r.route_prefix
        rows = []
        if r.ops.get("list"):
            rows.append(("GET", base, "liste paginée · ?q= ?sort= ?limit= ?offset="))
        if r.ops.get("create"):
            rows.append(("POST", base, "création → 201"))
        if r.ops.get("get"):
            rows.append(("GET", f"{base}/{{item_id}}", "lecture → 404 si absent"))
        if r.ops.get("update"):
            rows.append(("PUT", f"{base}/{{item_id}}", "remplacement complet"))
            rows.append(("PATCH", f"{base}/{{item_id}}", "mise à jour partielle"))
        if r.ops.get("delete"):
            rows.append(("DELETE", f"{base}/{{item_id}}", "suppression → 204"))
        return ft.Column([
            ft.Row([method_badge(m), ft.Text(path, font_family=MONO, size=13),
                    ft.Text(note, size=12, color=ft.Colors.ON_SURFACE_VARIANT)], spacing=12)
            for m, path, note in rows
        ], spacing=6)

    # ── Champs ───────────────────────────────────────────────────────
    def _add_field(self, r: Resource) -> None:
        existing = {f.name for f in r.fields}
        n = 1
        while f"field_{n}" in existing:
            n += 1
        r.fields.append(Field(f"field_{n}", "str", required=False))
        self._render_fields(r)
        self.fields_column.update()
        self._touch()

    def _render_fields(self, r: Resource) -> None:
        if not r.fields:
            self.fields_column.controls = [ft.Text("Aucun champ.", color=ft.Colors.ON_SURFACE_VARIANT)]
            return
        header = ft.Row(
            [ft.Text(t, size=12, weight=ft.FontWeight.W_600, color=ft.Colors.ON_SURFACE_VARIANT, **kw)
             for t, kw in (("Nom", {"expand": 3}), ("Type", {"width": 170}), ("Requis", {"width": 70}),
                           ("Unique", {"width": 70}), ("Max", {"width": 90}), ("Défaut", {"expand": 2}), ("", {"width": 96}))],
            spacing=8,
        )
        self.fields_column.controls = [header, *(self._field_row(r, i, f) for i, f in enumerate(r.fields))]

    def _field_row(self, r: Resource, index: int, f: Field) -> ft.Control:
        def set_value(attr):
            def handler(e):
                setattr(f, attr, e.control.value if attr in ("required", "unique") else (e.control.value or ""))
                if attr == "name":
                    f.name = f.name.strip()
                if attr == "type":  # le placeholder du défaut dépend du type
                    self._render_fields(r)
                    self.fields_column.update()
                self._touch()
            return handler

        def set_max_length(e):
            try:
                f.max_length = int(e.control.value)
            except (TypeError, ValueError):
                return
            self._touch()

        def move(delta):
            j = index + delta
            if 0 <= j < len(r.fields):
                r.fields[index], r.fields[j] = r.fields[j], r.fields[index]
                self._render_fields(r)
                self.fields_column.update()
                self.app.changed()

        def delete(_):
            r.fields.pop(index)
            self._render_fields(r)
            self.fields_column.update()
            self._touch()

        hint = {"bool": "true / false", "date": "AAAA-MM-JJ", "datetime": "AAAA-MM-JJTHH:MM"}.get(f.type, "")
        return ft.Row(
            [
                ft.TextField(value=f.name, dense=True, expand=3, on_change=set_value("name"),
                             text_style=ft.TextStyle(font_family=MONO), tooltip=f.description or None),
                ft.Dropdown(
                    value=f.type, width=170,
                    options=[ft.dropdown.Option(key=k, text=FIELD_TYPE_LABELS[k]) for k in FIELD_TYPES],
                    on_change=set_value("type"),
                ),
                ft.Container(ft.Checkbox(value=f.required, on_change=set_value("required"),
                                         tooltip="NOT NULL + obligatoire à la création"), width=70),
                ft.Container(ft.Checkbox(value=f.unique, on_change=set_value("unique"),
                                         tooltip="Contrainte UNIQUE → 409 en cas de doublon"), width=70),
                ft.TextField(value=str(f.max_length) if f.type == "str" else "—", dense=True, width=90,
                             disabled=f.type != "str", input_filter=ft.NumbersOnlyInputFilter(),
                             tooltip="Longueur maximale du texte", on_change=set_max_length),
                ft.TextField(value=f.default, dense=True, expand=2, hint_text=hint, on_change=set_value("default")),
                ft.Row([
                    ft.IconButton(ft.Icons.ARROW_UPWARD, icon_size=18, tooltip="Monter",
                                  disabled=index == 0, on_click=lambda _: move(-1)),
                    ft.IconButton(ft.Icons.DELETE_OUTLINE, icon_size=18, icon_color=ft.Colors.ERROR,
                                  tooltip="Supprimer le champ", on_click=delete),
                ], spacing=0, width=96),
            ],
            spacing=8,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        )
