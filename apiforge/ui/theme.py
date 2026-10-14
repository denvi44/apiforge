"""Briques visuelles Material 3 partagées par les vues."""
from __future__ import annotations

import io
import keyword
import platform
import tokenize

import flet as ft

SEED_COLOR = ft.Colors.INDIGO
MONO = {"Windows": "Consolas", "Darwin": "Menlo"}.get(platform.system(), "DejaVu Sans Mono")

METHOD_COLORS = {
    "GET": ft.Colors.GREEN_700,
    "POST": ft.Colors.BLUE_700,
    "PUT": ft.Colors.ORANGE_800,
    "PATCH": ft.Colors.PURPLE_600,
    "DELETE": ft.Colors.RED_700,
}

CODE_BG = "#1E1E2E"
CODE_FG = "#CDD6F4"
_SYNTAX = {
    "keyword": "#CBA6F7",
    "const": "#FAB387",
    "string": "#A6E3A1",
    "comment": "#7F849C",
    "number": "#FAB387",
    "decorator": "#F9E2AF",
    "defname": "#89B4FA",
    "type": "#F5C2E7",
}


def method_badge(method: str) -> ft.Control:
    return ft.Container(
        content=ft.Text(method, size=11, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE, font_family=MONO),
        bgcolor=METHOD_COLORS.get(method, ft.Colors.BLUE_GREY_600),
        border_radius=6,
        padding=ft.padding.symmetric(horizontal=8, vertical=3),
        width=66,
        alignment=ft.alignment.center,
    )


def page_header(title: str, subtitle: str, actions: list[ft.Control] | None = None) -> ft.Control:
    return ft.Row(
        [
            ft.Column(
                [
                    ft.Text(title, style=ft.TextThemeStyle.HEADLINE_SMALL, weight=ft.FontWeight.W_600),
                    ft.Text(subtitle, style=ft.TextThemeStyle.BODY_MEDIUM, color=ft.Colors.ON_SURFACE_VARIANT),
                ],
                spacing=2,
                expand=True,
            ),
            *(actions or []),
        ],
        vertical_alignment=ft.CrossAxisAlignment.CENTER,
    )


def section(title: str, icon: str, *controls: ft.Control, trailing: ft.Control | None = None,
            expand: bool | int = False) -> ft.Card:
    head = [ft.Icon(icon, color=ft.Colors.PRIMARY, size=20),
            ft.Text(title, style=ft.TextThemeStyle.TITLE_MEDIUM, expand=True)]
    if trailing:
        head.append(trailing)
    return ft.Card(
        elevation=1,
        expand=expand,
        content=ft.Container(
            padding=20,
            content=ft.Column([ft.Row(head), *controls], spacing=14, expand=bool(expand)),
        ),
    )


def empty_state(icon: str, title: str, text: str, action: ft.Control | None = None) -> ft.Control:
    return ft.Container(
        expand=True,
        alignment=ft.alignment.center,
        content=ft.Column(
            [
                ft.Icon(icon, size=56, color=ft.Colors.OUTLINE),
                ft.Text(title, style=ft.TextThemeStyle.TITLE_MEDIUM),
                ft.Text(text, color=ft.Colors.ON_SURFACE_VARIANT, text_align=ft.TextAlign.CENTER),
                *([action] if action else []),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            tight=True,
            spacing=10,
        ),
    )


def issues_banner(messages: list[str]) -> ft.Control:
    if not messages:
        return ft.Container(visible=False)
    return ft.Container(
        bgcolor=ft.Colors.ERROR_CONTAINER,
        border_radius=12,
        padding=14,
        content=ft.Column(
            [
                ft.Row([ft.Icon(ft.Icons.ERROR_OUTLINE, color=ft.Colors.ON_ERROR_CONTAINER),
                        ft.Text(f"{len(messages)} problème(s) à corriger", weight=ft.FontWeight.W_600,
                                color=ft.Colors.ON_ERROR_CONTAINER)]),
                *(ft.Text(f"• {m}", color=ft.Colors.ON_ERROR_CONTAINER, size=13) for m in messages),
            ],
            spacing=4,
        ),
    )


# ── Coloration syntaxique Python (tokenize stdlib → TextSpan) ────────────────
def _style(color: str | None, italic: bool = False) -> ft.TextStyle | None:
    if color is None:
        return None
    return ft.TextStyle(color=color, italic=italic)


def highlight_python(code: str) -> list[ft.TextSpan]:
    lines = code.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))

    def pos(row: int, col: int) -> int:
        return offsets[min(row - 1, len(lines))] + col

    string_types = {tokenize.STRING, *(getattr(tokenize, n) for n in ("FSTRING_START", "FSTRING_MIDDLE",
                                                                       "FSTRING_END") if hasattr(tokenize, n))}
    chunks: list[tuple[str, str | None, bool]] = []
    cursor = 0
    prev_name = ""
    prev_op = ""
    try:
        for tok in tokenize.generate_tokens(io.StringIO(code).readline):
            start, end = pos(*tok.start), pos(*tok.end)
            if start > cursor:
                chunks.append((code[cursor:start], None, False))
            text = code[start:end]
            color, italic = None, False
            if tok.type in string_types:
                color = _SYNTAX["string"]
            elif tok.type == tokenize.COMMENT:
                color, italic = _SYNTAX["comment"], True
            elif tok.type == tokenize.NUMBER:
                color = _SYNTAX["number"]
            elif tok.type == tokenize.NAME:
                if text in ("True", "False", "None"):
                    color = _SYNTAX["const"]
                elif keyword.iskeyword(text):
                    color = _SYNTAX["keyword"]
                elif prev_name in ("def", "class"):
                    color = _SYNTAX["defname"]
                elif prev_op == "@":
                    color = _SYNTAX["decorator"]
                elif text[:1].isupper():
                    color = _SYNTAX["type"]
            elif tok.type == tokenize.OP and text == "@":
                color = _SYNTAX["decorator"]
            if text:
                chunks.append((text, color, italic))
            cursor = max(cursor, end)
            if tok.type == tokenize.NAME:
                prev_name = text
            if tok.type not in (tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT):
                prev_op = text if tok.type == tokenize.OP else ""
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    if cursor < len(code):
        chunks.append((code[cursor:], None, False))

    # fusion des segments consécutifs de même style → beaucoup moins de contrôles
    spans: list[ft.TextSpan] = []
    buf, cur_style = "", (None, False)
    for text, color, italic in chunks:
        if (color, italic) == cur_style:
            buf += text
            continue
        if buf:
            spans.append(ft.TextSpan(buf, _style(*cur_style)))
        buf, cur_style = text, (color, italic)
    if buf:
        spans.append(ft.TextSpan(buf, _style(*cur_style)))
    return spans


def code_view(code: str, language: str = "python") -> ft.Control:
    spans = highlight_python(code) if language == "python" else None
    text = ft.Text(
        spans=spans,
        value=None if spans else code,
        selectable=True,
        font_family=MONO,
        size=13,
        color=CODE_FG,
        no_wrap=True,
    )
    return ft.Container(
        bgcolor=CODE_BG,
        border_radius=12,
        padding=16,
        expand=True,
        content=ft.Column(
            [ft.Row([text], scroll=ft.ScrollMode.AUTO)],
            scroll=ft.ScrollMode.AUTO,
            expand=True,
        ),
    )
