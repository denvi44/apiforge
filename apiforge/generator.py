"""Génération d'un projet FastAPI autonome à partir d'un `Project`.

Le code produit ne dépend que de FastAPI, Pydantic v2 et de sqlite3 (stdlib).
Toutes les chaînes utilisateur sont émises via `repr()` et tous les noms ont été
validés en amont : aucune donnée saisie n'est interpolée telle quelle dans le code.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import dataclass
from pathlib import Path

from .model import FIELD_TYPES, Endpoint, Issue, Project, Resource, coerce_default, parse_response, validate

GENERATOR_VERSION = "1.0"


class GenerationError(Exception):
    def __init__(self, issues: list[Issue]):
        super().__init__("\n".join(i.message for i in issues))
        self.issues = issues


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    summary: str


# ── Bloc runtime émis tel quel (pas de formatage : ne pas y mettre de jetons) ──
RUNTIME = r'''
DB_PATH = os.environ.get("APIFORGE_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.db"))


def _q(name: str) -> str:
    """Quote un identifiant SQL (les noms ont été validés à la génération)."""
    return '"' + name + '"'


def init_db() -> None:
    """Crée les tables et ajoute les colonnes manquantes (migration légère)."""
    with sqlite3.connect(DB_PATH) as conn:
        for table, (ddl, columns) in SCHEMA.items():
            conn.execute(ddl)
            existing = {row[1] for row in conn.execute(f"PRAGMA table_info({_q(table)})")}
            for column, sql_type in columns:
                if column not in existing:
                    conn.execute(f"ALTER TABLE {_q(table)} ADD COLUMN {_q(column)} {sql_type}")


def get_db() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _fetch_one(db: sqlite3.Connection, table: str, item_id: int) -> dict:
    row = db.execute(f"SELECT * FROM {_q(table)} WHERE id = ?", (item_id,)).fetchone()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{table} #{item_id} introuvable")
    return dict(row)


def _list_rows(db, table, columns, text_columns, limit, offset, q, sort) -> list[dict]:
    sql = f"SELECT * FROM {_q(table)}"
    params: list = []
    if q and text_columns:
        sql += " WHERE " + " OR ".join(f"{_q(c)} LIKE ?" for c in text_columns)
        params.extend([f"%{q}%"] * len(text_columns))
    order, direction = "id", "ASC"
    if sort:
        order = sort.lstrip("-")
        direction = "DESC" if sort.startswith("-") else "ASC"
        if order != "id" and order not in columns:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Tri impossible sur '{order}'")
    sql += f" ORDER BY {_q(order)} {direction} LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    return [dict(row) for row in db.execute(sql, params)]


def _insert(db: sqlite3.Connection, table: str, data: dict) -> dict:
    try:
        if data:
            cols = ", ".join(_q(c) for c in data)
            marks = ", ".join("?" for _ in data)
            cur = db.execute(f"INSERT INTO {_q(table)} ({cols}) VALUES ({marks})", list(data.values()))
        else:
            cur = db.execute(f"INSERT INTO {_q(table)} DEFAULT VALUES")
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Contrainte violée : {exc}") from exc
    return _fetch_one(db, table, cur.lastrowid)


def _update(db: sqlite3.Connection, table: str, item_id: int, data: dict) -> dict:
    _fetch_one(db, table, item_id)
    if data:
        assignments = ", ".join(f"{_q(c)} = ?" for c in data)
        try:
            db.execute(f"UPDATE {_q(table)} SET {assignments} WHERE id = ?", [*data.values(), item_id])
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, f"Contrainte violée : {exc}") from exc
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
'''

AUTH = r'''
API_KEY = os.environ.get("API_KEY", __DEFAULT_KEY__)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(key: Optional[str] = Security(_api_key_header)) -> None:
    if not key or not secrets.compare_digest(key, API_KEY):
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


def _field_line(field, *, partial: bool) -> str:
    annotation = FIELD_TYPES[field.type][0]
    default = None if partial else _default_literal(field)
    if partial or not field.required:
        annotation = f"Optional[{annotation}]"
        default = default or "None"
    if field.description:
        desc = repr(field.description)
        rhs = f"Field({default if default is not None else '...'}, description={desc})"
        return f"    {field.name}: {annotation} = {rhs}"
    if default is None:
        return f"    {field.name}: {annotation}"
    return f"    {field.name}: {annotation} = {default}"


def _resource_block(r: Resource) -> str:
    c, n = r.class_name, r.name
    up = n.upper()
    fields = r.fields
    base_body = "\n".join(_field_line(f, partial=False) for f in fields) or "    pass"
    upd_body = "\n".join(_field_line(f, partial=True) for f in fields) or "    pass"
    text_cols = tuple(f.name for f in fields if f.type == "str")
    tag = repr(n)
    L: list[str] = [
        f"# ── Ressource : {n} {'─' * max(0, 56 - len(n))}",
        f"class {c}Base(BaseModel):",
        base_body,
        "",
        "",
        f"class {c}Create({c}Base):",
        "    pass",
        "",
        "",
        f"class {c}Update(BaseModel):",
        upd_body,
        "",
        "",
        f"class {c}Out({c}Base):",
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
            "    limit: int = Query(50, ge=1, le=500),",
            "    offset: int = Query(0, ge=0),",
            '    q: Optional[str] = Query(None, description="Recherche plein texte sur les champs texte"),',
            "    sort: Optional[str] = Query(None, description=\"Champ de tri, préfixé de '-' pour l'ordre décroissant\"),",
            "    db: sqlite3.Connection = Depends(get_db),",
            "):",
            f"    return _list_rows(db, {up}_TABLE, {up}_COLUMNS, {up}_TEXT_COLUMNS, limit, offset, q, sort)",
            "",
        ]
    if r.ops.get("get"):
        L += [
            "",
            f'@router_{n}.get("/{{item_id}}", response_model={c}Out, summary={("Lire " + n)!r})',
            f"def get_{n}(item_id: int, db: sqlite3.Connection = Depends(get_db)):",
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
            f"def replace_{n}(item_id: int, payload: {c}Create, db: sqlite3.Connection = Depends(get_db)):",
            f'    return _update(db, {up}_TABLE, item_id, payload.model_dump(mode="json"))',
            "",
            "",
            f'@router_{n}.patch("/{{item_id}}", response_model={c}Out, summary={("Modifier partiellement " + n)!r})',
            f"def patch_{n}(item_id: int, payload: {c}Update, db: sqlite3.Connection = Depends(get_db)):",
            f'    return _update(db, {up}_TABLE, item_id, payload.model_dump(mode="json", exclude_unset=True))',
            "",
        ]
    if r.ops.get("delete"):
        L += [
            "",
            f'@router_{n}.delete("/{{item_id}}", status_code=status.HTTP_204_NO_CONTENT, summary={("Supprimer " + n)!r})',
            f"def delete_{n}(item_id: int, db: sqlite3.Connection = Depends(get_db)):",
            f"    _delete(db, {up}_TABLE, item_id)",
            "    return Response(status_code=status.HTTP_204_NO_CONTENT)",
            "",
        ]
    return "\n".join(L)


def _endpoint_block(i: int, e: Endpoint) -> str:
    params = e.path_params
    args = ", ".join(f"{p}: str" for p in params)
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


def generate_main(p: Project) -> str:
    issues = validate(p)
    if issues:
        raise GenerationError(issues)

    out: list[str] = [
        f'"""{_comment(p.name).replace(chr(92), "/").replace(chr(34), chr(39))} — API générée par APIForge {GENERATOR_VERSION}.',
        "",
        "Lancer :  uvicorn main:app --reload",
        "Docs   :  http://127.0.0.1:%d/docs" % int(p.port),
        '"""',
        "import datetime as _dt",
        "import os",
        "import secrets",
        "import sqlite3",
        "from contextlib import asynccontextmanager",
        "from typing import Iterator, Optional",
        "",
        "from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Response, Security, status",
        "from fastapi.middleware.cors import CORSMiddleware",
        "from fastapi.security import APIKeyHeader",
        "from pydantic import BaseModel, Field",
        "",
        "SCHEMA: dict = {",
        *(f"    {r.name!r}: ({_ddl(r)!r}, {[(f.name, FIELD_TYPES[f.type][1]) for f in r.fields]!r})," for r in p.resources),
        "}",
        RUNTIME,
    ]
    if p.api_key_enabled:
        out.append(AUTH.replace("__DEFAULT_KEY__", repr(p.api_key)))
    else:
        out.append("\nSECURED: list = []  # authentification par clé API désactivée\n")

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
        "    yield",
        "",
        "",
        f"app = FastAPI(title={p.name!r}, description={p.description!r}, version={p.version!r}, lifespan=lifespan)",
    ]
    if p.cors:
        out += [
            "app.add_middleware(",
            "    CORSMiddleware,",
            '    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),',
            '    allow_methods=["*"],',
            '    allow_headers=["*"],',
            ")",
        ]
    out += [
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
        f'    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", {int(p.port)})))',
        "",
    ]
    return "\n".join(out)


def generate_files(p: Project) -> dict[str, str]:
    """Tous les fichiers du projet exporté, nom -> contenu."""
    main = generate_main(p)
    routes = "\n".join(f"| `{r.method}` | `{r.path}` | {r.summary} |" for r in iter_routes(p))
    auth_note = (
        "Toutes les routes (sauf `/health`) exigent l'en-tête `X-API-Key`.\n"
        "Définis la clé via la variable d'environnement `API_KEY`.\n"
        if p.api_key_enabled else "Aucune authentification n'est activée.\n"
    )
    return {
        "main.py": main,
        "requirements.txt": "fastapi>=0.110\nuvicorn[standard]>=0.29\npydantic>=2.5\n",
        "Dockerfile": (
            "FROM python:3.12-slim\n"
            "WORKDIR /app\n"
            "ENV PYTHONUNBUFFERED=1 APIFORGE_DB=/data/data.db\n"
            "COPY requirements.txt .\n"
            "RUN pip install --no-cache-dir -r requirements.txt\n"
            "COPY main.py .\n"
            "VOLUME /data\n"
            f"EXPOSE {int(p.port)}\n"
            f'CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "{int(p.port)}"]\n'
        ),
        ".env.example": (
            ("API_KEY=change-me-please-32chars-min\n" if p.api_key_enabled else "")
            + "CORS_ORIGINS=*\nAPIFORGE_DB=./data.db\n"
        ),
        "README.md": (
            f"# {_comment(p.name)}\n\n{p.description}\n\n"
            "## Démarrage\n\n```bash\npython -m venv .venv && source .venv/bin/activate\n"
            "pip install -r requirements.txt\nuvicorn main:app --reload\n```\n\n"
            f"Documentation interactive : http://127.0.0.1:{int(p.port)}/docs\n\n"
            "## Docker\n\n```bash\n"
            f"docker build -t {p.slug} .\n"
            f"docker run -p {int(p.port)}:{int(p.port)} -v {p.slug}-data:/data {p.slug}\n```\n\n"
            f"## Sécurité\n\n{auth_note}\n"
            "## Routes\n\n| Méthode | Chemin | Description |\n|---|---|---|\n"
            f"{routes}\n\n"
            "Les listes acceptent `limit`, `offset`, `q` (recherche texte) et `sort` (`-champ` = décroissant).\n\n"
            "*Généré par APIForge.*\n"
        ),
    }


def export_project(p: Project, directory: str | Path) -> Path:
    target = Path(directory) / p.slug
    target.mkdir(parents=True, exist_ok=True)
    for name, content in generate_files(p).items():
        (target / name).write_text(content, encoding="utf-8")
    p.save(target / f"{p.slug}.apiforge.json")
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
