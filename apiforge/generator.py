"""Génération d'un projet FastAPI autonome à partir d'un `Project`.

Le code produit ne dépend que de FastAPI, Pydantic v2 et de sqlite3 (stdlib).
Toutes les chaînes utilisateur sont émises via `repr()` et tous les noms ont été
validés en amont : aucune donnée saisie n'est interpolée telle quelle dans le code.

Durcissement du code généré (voir SECURITY.md exporté) :
- aucun secret dans le source : clés API lues dans l'environnement, refus de démarrer sans
- schémas stricts (extra="forbid"), bornes de taille/valeur, PATCH sans null sur champs requis
- en-têtes de sécurité, limite de taille de corps, limitation de débit par IP
- erreurs SQL traduites sans fuite de schéma, LIKE échappé, SQLite en WAL
- docs désactivables, hôtes autorisés, conteneur non-root avec healthcheck
"""
from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import dataclass
from pathlib import Path

from .model import FIELD_TYPES, Endpoint, Issue, Project, Resource, coerce_default, parse_response, validate

GENERATOR_VERSION = "1.1"
SQLITE_INT_MAX = 2 ** 63 - 1
SQLITE_INT_MIN = -(2 ** 63)


class GenerationError(Exception):
    def __init__(self, issues: list[Issue]):
        super().__init__("\n".join(i.message for i in issues))
        self.issues = issues


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    summary: str


# ── Bloc runtime émis tel quel (chaîne brute : c'est le source exact du fichier généré) ──
RUNTIME = r'''
log = logging.getLogger("api")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise RuntimeError(f"Variable d'environnement {name} invalide : entier attendu") from None


def _env_list(name: str, default: str = "") -> list:
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


DB_PATH = os.environ.get("APIFORGE_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.db"))
MAX_BODY_BYTES = _env_int("MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES)
RATE_LIMIT_PER_MINUTE = _env_int("RATE_LIMIT_PER_MINUTE", DEFAULT_RATE_LIMIT)
DOCS_ENABLED = os.environ.get("DOCS_ENABLED", DEFAULT_DOCS).strip().lower() in ("1", "true", "yes", "oui")
ALLOWED_HOSTS = _env_list("ALLOWED_HOSTS")
CORS_ORIGINS = _env_list("CORS_ORIGINS", DEFAULT_CORS_ORIGINS)
HSTS_ENABLED = os.environ.get("HSTS", "").strip().lower() in ("1", "true", "yes", "oui")
DOC_PATHS = {"/docs", "/redoc", "/docs/oauth2-redirect"}


# ── Middlewares ASGI (purs : compatibles streaming, sans dépendance) ─────────
async def _send_json(send, status_code: int, detail: str, extra_headers=()) -> None:
    body = json.dumps({"detail": detail}, ensure_ascii=False).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status_code,
        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                    *extra_headers],
    })
    await send({"type": "http.response.body", "body": body})


class SecurityHeadersMiddleware:
    """En-têtes défensifs sur toutes les réponses ; CSP stricte hors pages de documentation."""

    COMMON = [
        (b"x-content-type-options", b"nosniff"),
        (b"x-frame-options", b"DENY"),
        (b"referrer-policy", b"no-referrer"),
        (b"cross-origin-opener-policy", b"same-origin"),
        (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
    ]
    API_ONLY = [
        (b"cache-control", b"no-store"),
        (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    ]

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        extra = list(self.COMMON)
        if scope["path"] not in DOC_PATHS:
            extra += self.API_ONLY
        if HSTS_ENABLED:
            extra.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() != b"server"]
                present = {k.lower() for k, _ in headers}
                headers += [(k, v) for k, v in extra if k not in present]
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


class _BodyTooLarge(HTTPException):
    def __init__(self):
        super().__init__(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Corps de requête trop volumineux")


class BodySizeLimitMiddleware:
    """Refuse les corps au-delà de MAX_BODY_BYTES (Content-Length annoncé ou flux réellement reçu)."""

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or self.max_bytes <= 0:
            return await self.app(scope, receive, send)
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    return await _send_json(send, 400, "En-tête Content-Length invalide")
                if declared > self.max_bytes:
                    return await _send_json(send, 413, "Corps de requête trop volumineux")
        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLarge()  # HTTPException : FastAPI la convertit en 413
            return message

        await self.app(scope, limited_receive, send)


class RateLimitMiddleware:
    """Fenêtre fixe d'une minute par IP cliente (mémoire du process : un compteur par worker)."""

    def __init__(self, app, per_minute: int):
        self.app = app
        self.per_minute = per_minute
        self._hits: dict = {}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or self.per_minute <= 0 or scope["path"] == "/health":
            return await self.app(scope, receive, send)
        now = time.time()
        window = int(now // 60)
        client = (scope.get("client") or ("inconnu", 0))[0]
        start, count = self._hits.get(client, (window, 0))
        if start != window:
            start, count = window, 0
        count += 1
        self._hits[client] = (start, count)
        if len(self._hits) > 50_000:  # borne mémoire : on purge les fenêtres expirées
            self._hits = {k: v for k, v in self._hits.items() if v[0] == window}
        if count > self.per_minute:
            retry_after = str(60 - int(now % 60)).encode()
            return await _send_json(send, 429, "Trop de requêtes, réessaie plus tard",
                                    [(b"retry-after", retry_after)])
        await self.app(scope, receive, send)


# ── Base de données ──────────────────────────────────────────────────────────
def _q(name: str) -> str:
    """Quote un identifiant SQL (les noms ont été validés à la génération)."""
    return '"' + name + '"'


def init_db() -> None:
    """Crée les tables, active WAL et ajoute les colonnes manquantes (migration légère)."""
    with sqlite3.connect(DB_PATH, timeout=10) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        for table, (ddl, columns) in SCHEMA.items():
            conn.execute(ddl)
            existing = {row[1] for row in conn.execute(f"PRAGMA table_info({_q(table)})")}
            for column, sql_type in columns:
                if column not in existing:
                    conn.execute(f"ALTER TABLE {_q(table)} ADD COLUMN {_q(column)} {sql_type}")
                    log.info("Colonne ajoutée : %s.%s", table, column)


def get_db() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _integrity_error(exc: sqlite3.IntegrityError) -> HTTPException:
    """Traduit une erreur de contrainte sans exposer le SQL ni le schéma interne."""
    message = str(exc)
    column = message.rsplit(".", 1)[-1].strip() if "." in message else ""
    if "UNIQUE" in message and column:
        return HTTPException(status.HTTP_409_CONFLICT, f"Valeur déjà utilisée pour « {column} »")
    if "NOT NULL" in message and column:
        return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Le champ « {column} » est obligatoire")
    log.warning("Contrainte SQLite non gérée : %s", message)
    return HTTPException(status.HTTP_409_CONFLICT, "Conflit de données")


def _fetch_one(db: sqlite3.Connection, table: str, item_id: int) -> dict:
    row = db.execute(f"SELECT * FROM {_q(table)} WHERE id = ?", (item_id,)).fetchone()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{table} #{item_id} introuvable")
    return dict(row)


def _like_pattern(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _list_rows(db, table, columns, text_columns, limit, offset, q, sort):
    where, params = "", []
    if q and text_columns:
        where = " WHERE " + " OR ".join(f"{_q(c)} LIKE ? ESCAPE '\\'" for c in text_columns)
        params = [_like_pattern(q)] * len(text_columns)
    total = db.execute(f"SELECT COUNT(*) FROM {_q(table)}{where}", params).fetchone()[0]
    order, direction = "id", "ASC"
    if sort:
        order = sort.lstrip("-")
        direction = "DESC" if sort.startswith("-") else "ASC"
        if order != "id" and order not in columns:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Tri impossible sur « {order} »")
    sql = f"SELECT * FROM {_q(table)}{where} ORDER BY {_q(order)} {direction}, id ASC LIMIT ? OFFSET ?"
    rows = [dict(row) for row in db.execute(sql, [*params, limit, offset])]
    return rows, total


def _insert(db: sqlite3.Connection, table: str, data: dict) -> dict:
    try:
        if data:
            cols = ", ".join(_q(c) for c in data)
            marks = ", ".join("?" for _ in data)
            cur = db.execute(f"INSERT INTO {_q(table)} ({cols}) VALUES ({marks})", list(data.values()))
        else:
            cur = db.execute(f"INSERT INTO {_q(table)} DEFAULT VALUES")
    except sqlite3.IntegrityError as exc:
        raise _integrity_error(exc) from None
    return _fetch_one(db, table, cur.lastrowid)


def _update(db: sqlite3.Connection, table: str, item_id: int, data: dict) -> dict:
    _fetch_one(db, table, item_id)
    if data:
        assignments = ", ".join(f"{_q(c)} = ?" for c in data)
        try:
            db.execute(f"UPDATE {_q(table)} SET {assignments} WHERE id = ?", [*data.values(), item_id])
        except sqlite3.IntegrityError as exc:
            raise _integrity_error(exc) from None
    return _fetch_one(db, table, item_id)


def _delete(db: sqlite3.Connection, table: str, item_id: int) -> None:
    _fetch_one(db, table, item_id)
    db.execute(f"DELETE FROM {_q(table)} WHERE id = ?", (item_id,))


def _render(value, params: dict):
    """Remplace les {param} des réponses personnalisées par les valeurs reçues."""
    if isinstance(value, str):
        for key, val in params.items():
            value = value.replace("{" + key + "}", str(val))
        return value
    if isinstance(value, list):
        return [_render(v, params) for v in value]
    if isinstance(value, dict):
        return {k: _render(v, params) for k, v in value.items()}
    return value


ItemId = Annotated[int, PathParam(ge=1, le=SQLITE_INT_MAX, description="Identifiant")]
'''

AUTH = r'''
# ── Authentification par clé API ─────────────────────────────────────────────
# Aucune clé n'est écrite dans ce fichier : API_KEYS (liste séparée par des virgules,
# pour permettre la rotation) ou API_KEY doivent être définies dans l'environnement.
API_KEYS = [k.encode("utf-8") for k in _env_list("API_KEYS", os.environ.get("API_KEY", ""))]
if not API_KEYS:
    raise RuntimeError("Aucune clé API configurée : définis API_KEYS (ou API_KEY) dans l'environnement.")
if any(len(k) < 16 for k in API_KEYS):
    raise RuntimeError("Chaque clé API doit faire au moins 16 caractères.")
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False, description="Clé d'accès à l'API")


def require_api_key(key: Optional[str] = Security(_api_key_header)) -> None:
    candidate = (key or "").encode("utf-8")
    # compare_digest sur chaque clé : temps constant, pas de court-circuit révélateur
    valid = [secrets.compare_digest(candidate, k) for k in API_KEYS]
    if not key or not any(valid):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Clé API invalide ou absente")


SECURED = [Depends(require_api_key)]
'''


def _comment(text: str) -> str:
    return " ".join(text.split())  # aucune fin de ligne ne peut sortir du commentaire


def _sql_column(field) -> str:
    sql_type = FIELD_TYPES[field.type][1]
    parts = [f'"{field.name}"', sql_type]
    if field.required:
        parts.append("NOT NULL")
    if field.unique:
        parts.append("UNIQUE")
    return " ".join(parts)


def _ddl(r: Resource) -> str:
    cols = ["id INTEGER PRIMARY KEY AUTOINCREMENT", *(_sql_column(f) for f in r.fields)]
    return f'CREATE TABLE IF NOT EXISTS "{r.name}" ({", ".join(cols)})'


def _default_literal(field) -> str | None:
    value = coerce_default(field)
    if value is None:
        return None
    if isinstance(value, _dt.datetime):
        return f"_dt.datetime.fromisoformat({value.isoformat()!r})"
    if isinstance(value, _dt.date):
        return f"_dt.date.fromisoformat({value.isoformat()!r})"
    return repr(value)


def _constraints(field, *, partial: bool) -> list[str]:
    """Bornes Pydantic : taille du texte, plage SQLite des entiers, pas de NaN/Infini."""
    kw: list[str] = []
    if field.type == "str":
        if field.required:  # aussi en PATCH : "" ne doit pas contourner l'obligation
            kw.append("min_length=1")
        kw.append(f"max_length={int(field.max_length)}")
    elif field.type == "int":
        kw += [f"ge={SQLITE_INT_MIN}", f"le={SQLITE_INT_MAX}"]
    elif field.type == "float":
        kw.append("allow_inf_nan=False")
    if field.description:
        kw.append(f"description={field.description!r}")
    return kw


def _field_line(field, *, partial: bool) -> str:
    annotation = FIELD_TYPES[field.type][0]
    default = None if partial else _default_literal(field)
    if partial or not field.required:
        annotation = f"Optional[{annotation}]"
        default = default or "None"
    kw = _constraints(field, partial=partial)
    if kw:
        return f"    {field.name}: {annotation} = Field({default if default is not None else '...'}, {', '.join(kw)})"
    if default is None:
        return f"    {field.name}: {annotation}"
    return f"    {field.name}: {annotation} = {default}"


STRICT = '    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)'


def _resource_block(r: Resource) -> str:
    c, n = r.class_name, r.name
    up = n.upper()
    fields = r.fields
    required = [f.name for f in fields if f.required]
    text_cols = tuple(f.name for f in fields if f.type == "str")
    tag = repr(n)
    L: list[str] = [
        f"# ── Ressource : {n} {'─' * max(0, 56 - len(n))}",
        f"class {c}Base(BaseModel):",
        STRICT,
        *(_field_line(f, partial=False) for f in fields),
        "",
        "",
        f"class {c}Create({c}Base):",
        "    pass",
        "",
        "",
        f"class {c}Update(BaseModel):",
        STRICT,
        *(_field_line(f, partial=True) for f in fields),
    ]
    if required:
        L += [
            "",
            f"    @field_validator({', '.join(repr(x) for x in required)})",
            "    @classmethod",
            "    def check_required_not_null(cls, value):",
            "        if value is None:",
            '            raise ValueError("ce champ est obligatoire et ne peut pas être nul")',
            "        return value",
        ]
    L += [
        "",
        "",
        f"class {c}Out({c}Base):",
        '    model_config = ConfigDict(extra="ignore")  # tolère les colonnes retirées du modèle',
        "    id: int",
        "",
        "",
        f"{up}_TABLE = {n!r}",
        f"{up}_COLUMNS = {tuple(f.name for f in fields)!r}",
        f"{up}_TEXT_COLUMNS = {text_cols!r}",
        f"router_{n} = APIRouter(prefix={r.route_prefix!r}, tags=[{tag}])",
        "",
    ]
    if r.ops.get("list"):
        L += [
            "",
            f'@router_{n}.get("", response_model=list[{c}Out], summary={("Lister " + n)!r})',
            f"def list_{n}(",
            "    response: Response,",
            "    limit: int = Query(50, ge=1, le=500),",
            "    offset: int = Query(0, ge=0, le=1_000_000),",
            '    q: Optional[str] = Query(None, max_length=100, description="Recherche plein texte sur les champs texte"),',
            "    sort: Optional[str] = Query(None, max_length=64, pattern=r\"^-?[a-z][a-z0-9_]*$\",",
            "                                description=\"Champ de tri, préfixé de '-' pour l'ordre décroissant\"),",
            "    db: sqlite3.Connection = Depends(get_db),",
            "):",
            f"    rows, total = _list_rows(db, {up}_TABLE, {up}_COLUMNS, {up}_TEXT_COLUMNS, limit, offset, q, sort)",
            '    response.headers["X-Total-Count"] = str(total)',
            "    return rows",
            "",
        ]
    if r.ops.get("get"):
        L += [
            "",
            f'@router_{n}.get("/{{item_id}}", response_model={c}Out, summary={("Lire " + n)!r})',
            f"def get_{n}(item_id: ItemId, db: sqlite3.Connection = Depends(get_db)):",
            f"    return _fetch_one(db, {up}_TABLE, item_id)",
            "",
        ]
    if r.ops.get("create"):
        L += [
            "",
            f'@router_{n}.post("", response_model={c}Out, status_code=status.HTTP_201_CREATED, summary={("Créer " + n)!r})',
            f"def create_{n}(payload: {c}Create, db: sqlite3.Connection = Depends(get_db)):",
            f'    return _insert(db, {up}_TABLE, payload.model_dump(mode="json"))',
            "",
        ]
    if r.ops.get("update"):
        L += [
            "",
            f'@router_{n}.put("/{{item_id}}", response_model={c}Out, summary={("Remplacer " + n)!r})',
            f"def replace_{n}(item_id: ItemId, payload: {c}Create, db: sqlite3.Connection = Depends(get_db)):",
            f'    return _update(db, {up}_TABLE, item_id, payload.model_dump(mode="json"))',
            "",
            "",
            f'@router_{n}.patch("/{{item_id}}", response_model={c}Out, summary={("Modifier partiellement " + n)!r})',
            f"def patch_{n}(item_id: ItemId, payload: {c}Update, db: sqlite3.Connection = Depends(get_db)):",
            f'    return _update(db, {up}_TABLE, item_id, payload.model_dump(mode="json", exclude_unset=True))',
            "",
        ]
    if r.ops.get("delete"):
        L += [
            "",
            f'@router_{n}.delete("/{{item_id}}", status_code=status.HTTP_204_NO_CONTENT, summary={("Supprimer " + n)!r})',
            f"def delete_{n}(item_id: ItemId, db: sqlite3.Connection = Depends(get_db)):",
            f"    _delete(db, {up}_TABLE, item_id)",
            "    return Response(status_code=status.HTTP_204_NO_CONTENT)",
            "",
        ]
    return "\n".join(L)


def _endpoint_block(i: int, e: Endpoint) -> str:
    params = e.path_params
    args = ", ".join(f"{p}: Annotated[str, PathParam(max_length=200)]" for p in params)
    summary = e.summary or f"{e.method} {e.path}"
    L = [
        "",
        f"@router_custom.{e.method.lower()}({e.path!r}, status_code={int(e.status_code)}, "
        f"summary={summary!r}, tags=[{(e.tag or 'custom')!r}])",
        f"def custom_{i}({args}):",
    ]
    if int(e.status_code) == 204:
        L.append("    return Response(status_code=204)")
    else:
        L.append(f"    _RESPONSE = {parse_response(e.response)!r}")
        mapping = "{" + ", ".join(f"{p!r}: {p}" for p in params) + "}"
        L.append(f"    return _render(_RESPONSE, {mapping})")
    L.append("")
    return "\n".join(L)


def _used_methods(p: Project) -> list[str]:
    methods = {"GET", "OPTIONS"}
    for r in p.resources:
        if r.ops.get("create"):
            methods.add("POST")
        if r.ops.get("update"):
            methods |= {"PUT", "PATCH"}
        if r.ops.get("delete"):
            methods.add("DELETE")
    methods |= {e.method for e in p.endpoints}
    return sorted(methods)


def generate_main(p: Project) -> str:
    issues = validate(p)
    if issues:
        raise GenerationError(issues)

    title = _comment(p.name).replace("\\", "/").replace('"', "'")
    out: list[str] = [
        f'"""{title} — API générée par APIForge {GENERATOR_VERSION}.',
        "",
        "Lancer :  uvicorn main:app --no-server-header",
        "Docs   :  http://127.0.0.1:%d/docs  (DOCS_ENABLED=0 pour les masquer)" % int(p.port),
        "Config :  variables d'environnement, voir .env.example et SECURITY.md",
        '"""',
        "import datetime as _dt",
        "import json",
        "import logging",
        "import os",
        "import secrets",
        "import sqlite3",
        "import time",
        "from contextlib import asynccontextmanager",
        "from typing import Annotated, Iterator, Optional",
        "",
        "from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Response, Security, status",
        "from fastapi import Path as PathParam",
        "from fastapi.middleware.cors import CORSMiddleware",
        "from fastapi.middleware.trustedhost import TrustedHostMiddleware",
        "from fastapi.security import APIKeyHeader",
        "from pydantic import BaseModel, ConfigDict, Field, field_validator",
        "",
        f"SQLITE_INT_MAX = {SQLITE_INT_MAX}",
        f"DEFAULT_MAX_BODY_BYTES = {int(p.max_body_kb) * 1024}",
        f"DEFAULT_RATE_LIMIT = {int(p.rate_limit)}",
        f"DEFAULT_DOCS = {('1' if p.docs_enabled else '0')!r}",
        f"DEFAULT_CORS_ORIGINS = {(p.cors_origins.strip() if p.cors else '')!r}",
        "",
        "SCHEMA: dict = {",
        *(f"    {r.name!r}: ({_ddl(r)!r}, {[(f.name, FIELD_TYPES[f.type][1]) for f in r.fields]!r})," for r in p.resources),
        "}",
        RUNTIME,
    ]
    if p.api_key_enabled:
        out.append(AUTH)
    else:
        out.append("\nSECURED: list = []  # authentification par clé API désactivée dans APIForge\n")

    for r in p.resources:
        out.append("\n" + _resource_block(r))

    if p.endpoints:
        out.append("\n# ── Endpoints personnalisés " + "─" * 46)
        out.append("router_custom = APIRouter()")
        for i, e in enumerate(p.endpoints):
            out.append(_endpoint_block(i, e))

    out += [
        "",
        "# ── Application " + "─" * 57,
        "@asynccontextmanager",
        "async def lifespan(_app: FastAPI):",
        "    init_db()",
        "    log.info(",
        '        "Démarrage — docs=%s, débit=%s req/min/IP, corps max=%s o, hôtes=%s, CORS=%s",',
        '        DOCS_ENABLED, RATE_LIMIT_PER_MINUTE or "illimité", MAX_BODY_BYTES, ALLOWED_HOSTS or "tous", CORS_ORIGINS or "aucun",',
        "    )",
        "    yield",
        "",
        "",
        "app = FastAPI(",
        f"    title={p.name!r},",
        f"    description={p.description!r},",
        f"    version={p.version!r},",
        "    lifespan=lifespan,",
        '    docs_url="/docs" if DOCS_ENABLED else None,',
        '    redoc_url="/redoc" if DOCS_ENABLED else None,',
        '    openapi_url="/openapi.json" if DOCS_ENABLED else None,',
        ")",
        "",
        "# Ordre : le dernier ajouté est le plus externe.",
        "app.add_middleware(BodySizeLimitMiddleware, max_bytes=MAX_BODY_BYTES)",
        "app.add_middleware(RateLimitMiddleware, per_minute=RATE_LIMIT_PER_MINUTE)",
        "if ALLOWED_HOSTS:",
        "    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)",
        "if CORS_ORIGINS:",
        "    app.add_middleware(",
        "        CORSMiddleware,",
        "        allow_origins=CORS_ORIGINS,",
        "        allow_credentials=False,",
        f"        allow_methods={_used_methods(p)!r},",
        f"        allow_headers={['Content-Type', 'X-API-Key'] if p.api_key_enabled else ['Content-Type']!r},",
        '        expose_headers=["X-Total-Count"],',
        "        max_age=600,",
        "    )",
        "app.add_middleware(SecurityHeadersMiddleware)",
        "",
        "",
        '@app.get("/health", tags=["system"], summary="État du service")',
        "def health():",
        '    return {"status": "ok"}',
        "",
        "",
    ]
    out += [f"app.include_router(router_{r.name}, dependencies=SECURED)" for r in p.resources]
    if p.endpoints:
        out.append("app.include_router(router_custom, dependencies=SECURED)")
    out += [
        "",
        "",
        'if __name__ == "__main__":',
        "    import uvicorn",
        "",
        "    logging.basicConfig(level=logging.INFO)",
        "    uvicorn.run(",
        "        app,",
        '        host=os.environ.get("HOST", "127.0.0.1"),',
        f'        port=_env_int("PORT", {int(p.port)}),',
        "        server_header=False,",
        "        proxy_headers=True,",
        "    )",
        "",
    ]
    return "\n".join(out)


def _security_md(p: Project) -> str:
    auth = (
        "- **Clé API obligatoire** (en-tête `X-API-Key`) sur toutes les routes sauf `/health` et la documentation.\n"
        "  Aucune clé n'est écrite dans le code : l'API **refuse de démarrer** sans `API_KEYS`.\n"
        "  Plusieurs clés séparées par des virgules permettent une rotation sans coupure.\n"
        if p.api_key_enabled else
        "- ⚠️ **Aucune authentification** : n'expose pas cette API sur Internet sans en ajouter une.\n"
    )
    return (
        "# Sécurité\n\n"
        "## Mesures intégrées\n\n"
        f"{auth}"
        "- Schémas stricts : champs inconnus refusés (422), textes bornés en longueur, entiers bornés à 64 bits,\n"
        "  décimaux sans NaN/Infini, champs requis non nullables en PATCH.\n"
        "- SQL paramétré, identifiants validés à la génération, tri sur liste blanche, `LIKE` échappé.\n"
        "- Erreurs de contrainte traduites (409/422) sans fuite du SQL ni du schéma.\n"
        "- En-têtes : `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, CSP `default-src 'none'`,\n"
        "  `Cache-Control: no-store` sur l'API, en-tête `Server` supprimé, HSTS optionnel.\n"
        "- Limite de taille du corps (413) et de débit par IP (429 + `Retry-After`).\n"
        "- CORS restreint aux méthodes réellement exposées, sans cookies (`allow_credentials=False`).\n"
        "- Conteneur non-root, healthcheck, base SQLite dans un volume.\n\n"
        "## Variables d'environnement\n\n"
        "| Variable | Défaut | Rôle |\n|---|---|---|\n"
        + ("| `API_KEYS` | *(obligatoire)* | Clés acceptées, séparées par des virgules (16 caractères min.) |\n"
           if p.api_key_enabled else "")
        + f"| `CORS_ORIGINS` | `{p.cors_origins if p.cors else ''}` | Origines autorisées (vide = CORS désactivé) |\n"
        "| `ALLOWED_HOSTS` | *(vide = tous)* | Valeurs acceptées pour l'en-tête `Host`, ex. `api.exemple.fr` |\n"
        f"| `RATE_LIMIT_PER_MINUTE` | `{p.rate_limit}` | Requêtes par minute et par IP (`0` = désactivé) |\n"
        f"| `MAX_BODY_BYTES` | `{p.max_body_kb * 1024}` | Taille maximale d'un corps de requête |\n"
        f"| `DOCS_ENABLED` | `{'1' if p.docs_enabled else '0'}` | Swagger / ReDoc / OpenAPI |\n"
        "| `HSTS` | `0` | Active `Strict-Transport-Security` (seulement derrière HTTPS) |\n"
        "| `APIFORGE_DB` | `./data.db` | Chemin de la base SQLite |\n\n"
        "## Avant la mise en production\n\n"
        "1. Servir l'API derrière un reverse proxy **HTTPS** (Caddy, Traefik, Nginx), puis `HSTS=1`.\n"
        "2. Remplacer `CORS_ORIGINS=*` par la liste exacte des front-ends, renseigner `ALLOWED_HOSTS`.\n"
        "3. `DOCS_ENABLED=0` si la documentation ne doit pas être publique.\n"
        "4. Derrière un proxy, définir `FORWARDED_ALLOW_IPS` (uvicorn) à l'IP du proxy pour que la\n"
        "   limitation de débit voie la vraie IP cliente.\n"
        "5. Le compteur de débit est propre à chaque worker : avec plusieurs workers ou instances,\n"
        "   déléguer la limitation au reverse proxy ou à une passerelle.\n"
        "6. Sauvegarder le volume `/data` ; ne jamais committer `.env` ni `data.db`.\n\n"
        "## Hors périmètre\n\n"
        "Pas de comptes utilisateurs ni de droits par ressource : toute clé valide donne accès à tout.\n"
        "Pour du multi-utilisateur, ajouter OAuth2/JWT et un contrôle d'accès par propriétaire.\n"
    )


def generate_files(p: Project) -> dict[str, str]:
    """Tous les fichiers du projet exporté, nom -> contenu."""
    main = generate_main(p)
    port = int(p.port)
    routes = "\n".join(f"| `{r.method}` | `{r.path}` | {r.summary} |" for r in iter_routes(p))
    auth_note = (
        "Toutes les routes (sauf `/health`) exigent l'en-tête `X-API-Key`.\n"
        "L'API refuse de démarrer si `API_KEYS` n'est pas défini.\n"
        if p.api_key_enabled else "Aucune authentification n'est activée.\n"
    )
    run_env = "export API_KEYS=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')\n" \
        if p.api_key_enabled else ""
    return {
        "main.py": main,
        "requirements.txt": "fastapi>=0.110,<1.0\nuvicorn[standard]>=0.29,<1.0\npydantic>=2.5,<3.0\n",
        "Dockerfile": (
            "FROM python:3.12-slim\n\n"
            "ENV PYTHONUNBUFFERED=1 \\\n    PYTHONDONTWRITEBYTECODE=1 \\\n    APIFORGE_DB=/data/data.db\n\n"
            "WORKDIR /app\n"
            "RUN useradd --create-home --uid 10001 app && mkdir -p /data && chown app:app /data\n"
            "COPY requirements.txt .\n"
            "RUN pip install --no-cache-dir -r requirements.txt\n"
            "COPY --chown=app:app main.py .\n\n"
            "USER app\n"
            "VOLUME /data\n"
            f"EXPOSE {port}\n\n"
            "HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \\\n"
            f"  CMD python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:{port}/health', timeout=2)\" || exit 1\n\n"
            f'CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "{port}", "--no-server-header", "--proxy-headers"]\n'
        ),
        ".dockerignore": ".env\n*.db\n*.db-*\n__pycache__/\n.venv/\n.git/\n",
        ".gitignore": ".env\n*.db\n*.db-shm\n*.db-wal\n__pycache__/\n.venv/\n",
        ".env.example": (
            ("# Générer : python -c \"import secrets; print(secrets.token_urlsafe(32))\"\n"
             "API_KEYS=remplace-moi-par-une-cle-aleatoire-de-32-caracteres\n" if p.api_key_enabled else "")
            + f"CORS_ORIGINS={p.cors_origins if p.cors else ''}\n"
            "ALLOWED_HOSTS=\n"
            f"RATE_LIMIT_PER_MINUTE={p.rate_limit}\n"
            f"MAX_BODY_BYTES={p.max_body_kb * 1024}\n"
            f"DOCS_ENABLED={'1' if p.docs_enabled else '0'}\n"
            "HSTS=0\n"
            "APIFORGE_DB=./data.db\n"
        ),
        "SECURITY.md": _security_md(p),
        "README.md": (
            f"# {_comment(p.name)}\n\n{p.description}\n\n"
            "## Démarrage\n\n```bash\npython -m venv .venv && source .venv/bin/activate\n"
            f"pip install -r requirements.txt\n{run_env}uvicorn main:app --reload --no-server-header\n```\n\n"
            f"Documentation interactive : http://127.0.0.1:{port}/docs\n\n"
            "## Docker\n\n```bash\n"
            f"docker build -t {p.slug} .\n"
            f"docker run -p {port}:{port} --env-file .env -v {p.slug}-data:/data {p.slug}\n```\n\n"
            f"## Sécurité\n\n{auth_note}Détails et checklist de production : [SECURITY.md](SECURITY.md).\n\n"
            "## Routes\n\n| Méthode | Chemin | Description |\n|---|---|---|\n"
            f"{routes}\n\n"
            "Les listes acceptent `limit`, `offset`, `q` (recherche texte) et `sort` (`-champ` = décroissant) ;\n"
            "le total est renvoyé dans l'en-tête `X-Total-Count`.\n\n"
            "*Généré par APIForge.*\n"
        ),
    }


def export_project(p: Project, directory: str | Path) -> Path:
    target = Path(directory) / p.slug
    target.mkdir(parents=True, exist_ok=True)
    for name, content in generate_files(p).items():
        (target / name).write_text(content, encoding="utf-8")
    exported = Project.from_dict(p.to_dict())
    exported.api_key = ""  # la clé de test du serveur intégré ne quitte pas APIForge
    exported.save(target / f"{p.slug}.apiforge.json")
    return target


def iter_routes(p: Project) -> list[Route]:
    routes = [Route("GET", "/health", "État du service")]
    for r in p.resources:
        base = r.route_prefix
        if r.ops.get("list"):
            routes.append(Route("GET", base, f"Lister {r.name}"))
        if r.ops.get("create"):
            routes.append(Route("POST", base, f"Créer {r.name}"))
        if r.ops.get("get"):
            routes.append(Route("GET", f"{base}/{{item_id}}", f"Lire {r.name}"))
        if r.ops.get("update"):
            routes.append(Route("PUT", f"{base}/{{item_id}}", f"Remplacer {r.name}"))
            routes.append(Route("PATCH", f"{base}/{{item_id}}", f"Modifier {r.name}"))
        if r.ops.get("delete"):
            routes.append(Route("DELETE", f"{base}/{{item_id}}", f"Supprimer {r.name}"))
    for e in p.endpoints:
        routes.append(Route(e.method, e.path, e.summary or "Endpoint personnalisé"))
    return routes


def code_hash(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()[:16]
