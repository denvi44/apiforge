"""Modèle de données d'un projet APIForge + validation.

Tout ce qui finit dans le code généré passe par `validate()` : les noms sont
des identifiants Python/SQL stricts, les chemins sont filtrés, les JSON parsés.
C'est ce qui permet au générateur d'émettre du code sans risque d'injection.
"""
from __future__ import annotations

import datetime as _dt
import json
import keyword
import math
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

SCHEMA_VERSION = 1

# type logique -> (annotation Python, type SQLite)
FIELD_TYPES: dict[str, tuple[str, str]] = {
    "str": ("str", "TEXT"),
    "int": ("int", "INTEGER"),
    "float": ("float", "REAL"),
    "bool": ("bool", "INTEGER"),
    "date": ("_dt.date", "TEXT"),
    "datetime": ("_dt.datetime", "TEXT"),
}
FIELD_TYPE_LABELS = {
    "str": "Texte",
    "int": "Entier",
    "float": "Décimal",
    "bool": "Booléen",
    "date": "Date",
    "datetime": "Date & heure",
}
HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
CRUD_OPS = ("list", "get", "create", "update", "delete")
CRUD_LABELS = {
    "list": "Lister",
    "get": "Lire",
    "create": "Créer",
    "update": "Modifier",
    "delete": "Supprimer",
}

IDENT_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
RESOURCE_PATH_RE = re.compile(r"^(/[a-z0-9][a-z0-9_\-]*)+$")
SEGMENT_RE = re.compile(r"^(\{[a-z][a-z0-9_]*\}|[A-Za-z0-9_\-.~]+)$")
PARAM_RE = re.compile(r"\{([a-z][a-z0-9_]*)\}")

# Noms qui entreraient en collision avec le code généré ou Pydantic.
RESERVED_FIELD_NAMES = {
    "id", "str", "int", "float", "bool", "date", "datetime", "db",
    "limit", "offset", "q", "sort", "payload", "item_id",
    # attributs hérités de pydantic.BaseModel
    "json", "dict", "copy", "schema", "schema_json", "construct", "validate",
    "parse_obj", "parse_raw", "parse_file", "from_orm", "update_forward_refs", "fields",
    "check_required_not_null",
}
RESERVED_RESOURCE_NAMES = {"custom", "health", "system", "docs", "redoc", "openapi"}
TRUE_VALUES = {"true", "1", "oui", "yes", "vrai"}
FALSE_VALUES = {"false", "0", "non", "no", "faux"}


@dataclass
class Field:
    name: str
    type: str = "str"
    required: bool = True
    unique: bool = False
    default: str = ""
    description: str = ""
    max_length: int = 255  # texte uniquement : borne la taille stockée


@dataclass
class Resource:
    name: str
    fields: list[Field] = field(default_factory=list)
    ops: dict[str, bool] = field(default_factory=lambda: {op: True for op in CRUD_OPS})
    path: str = ""
    description: str = ""

    @property
    def route_prefix(self) -> str:
        if self.path:
            return self.path
        return f"/{self.name}" if self.name.endswith("s") else f"/{self.name}s"

    @property
    def class_name(self) -> str:
        return "".join(part.capitalize() for part in self.name.split("_") if part)


@dataclass
class Endpoint:
    method: str = "GET"
    path: str = "/hello/{name}"
    summary: str = ""
    status_code: int = 200
    response: str = '{"message": "Bonjour {name} !"}'
    tag: str = "custom"

    @property
    def path_params(self) -> list[str]:
        return PARAM_RE.findall(self.path)


@dataclass
class Project:
    name: str = "Mon API"
    description: str = ""
    version: str = "1.0.0"
    port: int = 8000
    cors: bool = True
    api_key_enabled: bool = False
    api_key: str = ""  # utilisée uniquement par le serveur intégré, jamais écrite dans le code généré
    cors_origins: str = "*"
    rate_limit: int = 120  # requêtes / minute / IP, 0 = désactivé
    max_body_kb: int = 1024
    docs_enabled: bool = True
    resources: list[Resource] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)

    # ── Sérialisation ────────────────────────────────────────────────
    def to_dict(self) -> dict:
        return {"schema": SCHEMA_VERSION, **asdict(self)}

    @classmethod
    def from_dict(cls, data: dict) -> "Project":
        data = dict(data)
        data.pop("schema", None)
        resources = [
            Resource(
                name=r.get("name", ""),
                fields=[Field(**_known(Field, f)) for f in r.get("fields", [])],
                ops={op: bool(r.get("ops", {}).get(op, True)) for op in CRUD_OPS},
                path=r.get("path", ""),
                description=r.get("description", ""),
            )
            for r in data.pop("resources", [])
        ]
        endpoints = [Endpoint(**_known(Endpoint, e)) for e in data.pop("endpoints", [])]
        return cls(**_known(cls, data), resources=resources, endpoints=endpoints)

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)  # écriture atomique

    @classmethod
    def load(cls, path: str | Path) -> "Project":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    @property
    def slug(self) -> str:
        slug = re.sub(r"[^a-z0-9]+", "-", self.name.lower()).strip("-")
        return slug or "api"

    # ── Fabriques ────────────────────────────────────────────────────
    @classmethod
    def sample(cls) -> "Project":
        return cls(
            name="Boutique API",
            description="API d'exemple générée avec APIForge.",
            resources=[
                Resource(
                    name="product",
                    description="Produits du catalogue",
                    fields=[
                        Field("title", "str", required=True, unique=True, description="Nom du produit"),
                        Field("price", "float", required=True),
                        Field("in_stock", "bool", required=False, default="true"),
                        Field("released", "date", required=False),
                    ],
                ),
                Resource(
                    name="customer",
                    fields=[
                        Field("full_name", "str"),
                        Field("email", "str", unique=True),
                        Field("vip", "bool", required=False, default="false"),
                    ],
                ),
            ],
            endpoints=[Endpoint(summary="Message de bienvenue")],
        )


def _known(klass, data: dict) -> dict:
    """Ignore les clés inconnues (fichiers produits par une version plus récente)."""
    allowed = klass.__dataclass_fields__.keys()
    return {k: v for k, v in data.items() if k in allowed and k not in ("resources", "endpoints", "fields")}


# ── Validation ───────────────────────────────────────────────────────
@dataclass(frozen=True)
class Issue:
    where: str      # "project", "resource:<i>", "endpoint:<i>"
    message: str


def coerce_default(f: Field):
    """Convertit la valeur par défaut saisie en valeur Python typée. Lève ValueError."""
    raw = f.default.strip()
    if raw == "":
        return None
    if f.type == "str":
        return f.default
    if f.type == "int":
        return int(raw)
    if f.type == "float":
        return float(raw)
    if f.type == "bool":
        low = raw.lower()
        if low in TRUE_VALUES:
            return True
        if low in FALSE_VALUES:
            return False
        raise ValueError(raw)
    if f.type == "date":
        return _dt.date.fromisoformat(raw)
    if f.type == "datetime":
        return _dt.datetime.fromisoformat(raw)
    raise ValueError(f.type)


def parse_response(text: str):
    """Parse le JSON d'une réponse personnalisée (refuse NaN/Infinity)."""
    def _reject(const):
        raise ValueError(f"constante non supportée : {const}")
    return json.loads(text, parse_constant=_reject)


def _check_ident(name: str) -> str | None:
    if not name:
        return "nom vide"
    if not IDENT_RE.match(name):
        return "minuscules, chiffres et _ uniquement, commence par une lettre (40 car. max)"
    if keyword.iskeyword(name) or keyword.issoftkeyword(name):
        return "mot réservé Python"
    return None


def validate(p: Project) -> list[Issue]:
    issues: list[Issue] = []
    add = lambda where, msg: issues.append(Issue(where, msg))  # noqa: E731

    if not p.name.strip():
        add("project", "Le nom de l'API est obligatoire.")
    if not 1 <= int(p.port) <= 65535:
        add("project", "Le port doit être compris entre 1 et 65535.")
    if p.api_key_enabled and len(p.api_key) < 16:
        add("project", "La clé API doit faire au moins 16 caractères.")
    if p.api_key_enabled and (not p.api_key.isascii() or "," in p.api_key or p.api_key != p.api_key.strip()):
        add("project", "La clé API doit être en ASCII, sans virgule ni espace en bordure.")
    if not 0 <= int(p.rate_limit) <= 100_000:
        add("project", "La limite de requêtes doit être comprise entre 0 et 100 000 par minute.")
    if not 1 <= int(p.max_body_kb) <= 1_048_576:
        add("project", "La taille maximale du corps doit être comprise entre 1 Ko et 1 Go.")
    if p.cors and not p.cors_origins.strip():
        add("project", "Indique au moins une origine CORS (ou « * »).")
    if not p.resources and not p.endpoints:
        add("project", "Ajoute au moins une ressource ou un endpoint.")

    seen_names: set[str] = set()
    seen_prefixes: set[str] = set()
    for i, r in enumerate(p.resources):
        where = f"resource:{i}"
        label = r.name or f"#{i + 1}"
        if err := _check_ident(r.name):
            add(where, f"Ressource « {label} » : nom invalide ({err}).")
        elif r.name in RESERVED_RESOURCE_NAMES:
            add(where, f"Ressource « {label} » : nom réservé.")
        elif r.name in seen_names:
            add(where, f"Ressource « {label} » : nom en double.")
        seen_names.add(r.name)

        if r.path and not RESOURCE_PATH_RE.match(r.path):
            add(where, f"Ressource « {label} » : chemin invalide (ex. /produits).")
        if r.route_prefix in seen_prefixes:
            add(where, f"Ressource « {label} » : chemin {r.route_prefix} déjà utilisé.")
        seen_prefixes.add(r.route_prefix)
        if not any(r.ops.values()):
            add(where, f"Ressource « {label} » : aucune opération activée.")

        seen_fields: set[str] = set()
        for f in r.fields:
            flabel = f.name or "(vide)"
            if err := _check_ident(f.name):
                add(where, f"Champ « {flabel} » : nom invalide ({err}).")
            elif f.name in RESERVED_FIELD_NAMES or f.name.startswith("model_"):
                add(where, f"Champ « {flabel} » : nom réservé.")
            elif f.name in seen_fields:
                add(where, f"Champ « {flabel} » : nom en double.")
            seen_fields.add(f.name)
            if f.type not in FIELD_TYPES:
                add(where, f"Champ « {flabel} » : type inconnu ({f.type}).")
                continue
            if f.type == "str" and not 1 <= int(f.max_length) <= 1_000_000:
                add(where, f"Champ « {flabel} » : longueur maximale entre 1 et 1 000 000.")
            try:
                value = coerce_default(f)
                if f.type == "str" and value is not None and len(value) > int(f.max_length):
                    add(where, f"Champ « {flabel} » : la valeur par défaut dépasse la longueur maximale.")
                if f.type == "int" and value is not None and not -(2 ** 63) <= value < 2 ** 63:
                    add(where, f"Champ « {flabel} » : valeur par défaut hors limites SQLite (64 bits).")
                if f.type == "float" and value is not None and not math.isfinite(value):
                    raise ValueError
            except ValueError:
                add(where, f"Champ « {flabel} » : valeur par défaut invalide pour le type {FIELD_TYPE_LABELS[f.type]}.")

    seen_routes: set[tuple[str, str]] = set()
    for i, e in enumerate(p.endpoints):
        where = f"endpoint:{i}"
        label = f"{e.method} {e.path}"
        if e.method not in HTTP_METHODS:
            add(where, f"Endpoint « {label} » : méthode inconnue.")
        segments = e.path.split("/")[1:] if e.path.startswith("/") else None
        if not segments or not all(SEGMENT_RE.match(s) for s in segments):
            add(where, f"Endpoint « {label} » : chemin invalide (ex. /hello/{{name}}).")
        else:
            params = e.path_params
            if len(params) != len(set(params)):
                add(where, f"Endpoint « {label} » : paramètre de chemin en double.")
            for prm in params:
                if keyword.iskeyword(prm) or prm in RESERVED_FIELD_NAMES:
                    add(where, f"Endpoint « {label} » : paramètre « {prm} » réservé.")
        if (e.method, e.path) in seen_routes:
            add(where, f"Endpoint « {label} » : déclaré deux fois.")
        seen_routes.add((e.method, e.path))
        if not 100 <= int(e.status_code) <= 599:
            add(where, f"Endpoint « {label} » : code HTTP invalide.")
        if e.status_code != 204:
            try:
                parse_response(e.response)
            except ValueError as exc:
                add(where, f"Endpoint « {label} » : JSON de réponse invalide ({exc}).")
    return issues
