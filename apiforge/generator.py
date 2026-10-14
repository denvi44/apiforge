"""Génération d'un projet FastAPI autonome à partir d'un `Project`.

Le code produit dépend de FastAPI, Pydantic v2 et sqlite3 (stdlib), plus PyJWT et
python-multipart quand les comptes utilisateurs sont activés.
Toutes les chaînes utilisateur sont émises via `repr()` et tous les noms ont été
validés en amont : aucune donnée saisie n'est interpolée telle quelle dans le code.

Durcissement (détaillé dans le SECURITY.md exporté) :
- aucun secret dans le source : clés API et secret JWT lus dans l'environnement, refus de démarrer sans
- comptes utilisateurs : mots de passe scrypt, JWT HS256 révocables, contrôle d'accès par ressource
- schémas stricts, bornes de taille/valeur, erreurs SQL non divulguées, LIKE échappé
- en-têtes de sécurité, limite de corps, limitation de débit partagée (SQLite ou Redis)
"""
from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import dataclass
from pathlib import Path

from .model import FIELD_TYPES, Endpoint, Issue, Project, Resource, coerce_default, parse_response, validate

GENERATOR_VERSION = "1.2"
SQLITE_INT_MAX = 2 ** 63 - 1
SQLITE_INT_MIN = -(2 ** 63)
OWNER_DDL = 'INTEGER REFERENCES "users"(id) ON DELETE CASCADE'


class GenerationError(Exception):
    def __init__(self, issues: list[Issue]):
        super().__init__("\n".join(i.message for i in issues))
        self.issues = issues


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    summary: str


def is_owned(p: Project, r: Resource) -> bool:
    return p.users_enabled and r.access == "owner"


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


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "oui")


def _env_list(name: str, default: str = "") -> list:
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


DB_PATH = os.environ.get("APIFORGE_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.db"))
MAX_BODY_BYTES = _env_int("MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES)
RATE_LIMIT_PER_MINUTE = _env_int("RATE_LIMIT_PER_MINUTE", DEFAULT_RATE_LIMIT)
AUTH_RATE_LIMIT_PER_MINUTE = _env_int("AUTH_RATE_LIMIT_PER_MINUTE", 10)
RATE_LIMIT_BACKEND = os.environ.get("RATE_LIMIT_BACKEND", "sqlite").strip().lower()
REDIS_URL = os.environ.get("REDIS_URL", "")
DOCS_ENABLED = _env_bool("DOCS_ENABLED", DEFAULT_DOCS)
ALLOWED_HOSTS = _env_list("ALLOWED_HOSTS")
CORS_ORIGINS = _env_list("CORS_ORIGINS", DEFAULT_CORS_ORIGINS)
HSTS_ENABLED = _env_bool("HSTS", False)
DOC_PATHS = {"/docs", "/redoc", "/docs/oauth2-redirect"}
AUTH_PATHS = {"/auth/token", "/auth/register", "/auth/password"}

if RATE_LIMIT_BACKEND not in ("sqlite", "redis", "memory"):
    raise RuntimeError("RATE_LIMIT_BACKEND doit valoir sqlite, redis ou memory")
if RATE_LIMIT_BACKEND == "redis" and not REDIS_URL:
    raise RuntimeError("RATE_LIMIT_BACKEND=redis exige REDIS_URL (ex. redis://redis:6379/0)")


# ── Middlewares ASGI (purs : compatibles streaming) ──────────────────────────
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


class MemoryCounter:
    """Compteur local au process : uniquement pour le développement avec un seul worker."""

    def __init__(self):
        self._hits: dict = {}

    async def hit(self, bucket: str, win: int) -> int:
        start, count = self._hits.get(bucket, (win, 0))
        count = count + 1 if start == win else 1
        self._hits[bucket] = (win, count)
        if len(self._hits) > 50_000:
            self._hits = {k: v for k, v in self._hits.items() if v[0] == win}
        return count


class SqliteCounter:
    """Compteur partagé par tous les workers d'une même machine (même fichier SQLite)."""

    def __init__(self, path: str):
        self.path = path
        self._local = threading.local()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=5, isolation_level=None)
            conn.execute(
                "CREATE TABLE IF NOT EXISTS _rate_limit (bucket TEXT NOT NULL, win INTEGER NOT NULL, "
                "hits INTEGER NOT NULL, PRIMARY KEY (bucket, win)) WITHOUT ROWID"
            )
            self._local.conn = conn
        return conn

    def _hit_sync(self, bucket: str, win: int) -> int:
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")  # sérialise les workers : incrément atomique
        try:
            conn.execute(
                "INSERT INTO _rate_limit (bucket, win, hits) VALUES (?, ?, 1) "
                "ON CONFLICT(bucket, win) DO UPDATE SET hits = hits + 1",
                (bucket, win),
            )
            hits = conn.execute("SELECT hits FROM _rate_limit WHERE bucket = ? AND win = ?", (bucket, win)).fetchone()[0]
            if hits == 1 and win % 5 == 0:
                conn.execute("DELETE FROM _rate_limit WHERE win < ?", (win - 1,))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        return hits

    async def hit(self, bucket: str, win: int) -> int:
        return await anyio.to_thread.run_sync(self._hit_sync, bucket, win)


class RedisCounter:
    """Compteur partagé entre plusieurs machines/instances."""

    def __init__(self, url: str):
        try:
            import redis.asyncio as aioredis
        except ImportError:
            raise RuntimeError("RATE_LIMIT_BACKEND=redis nécessite le paquet « redis » (pip install redis)") from None
        self._redis = aioredis.from_url(url)

    async def hit(self, bucket: str, win: int) -> int:
        key = f"ratelimit:{bucket}:{win}"
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.incr(key)
            pipe.expire(key, 120)
            hits, _ = await pipe.execute()
        return int(hits)


def _make_counter():
    if RATE_LIMIT_BACKEND == "redis":
        return RedisCounter(REDIS_URL)
    if RATE_LIMIT_BACKEND == "memory":
        return MemoryCounter()
    return SqliteCounter(DB_PATH)


class RateLimitMiddleware:
    """Fenêtre fixe d'une minute par IP ; limite plus stricte sur les routes d'authentification."""

    def __init__(self, app, per_minute: int, auth_per_minute: int):
        self.app = app
        self.per_minute = per_minute
        self.auth_per_minute = auth_per_minute
        self.counter = _make_counter() if (per_minute > 0 or auth_per_minute > 0) else None

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or self.counter is None or scope["path"] == "/health":
            return await self.app(scope, receive, send)
        is_auth = scope["method"] == "POST" and scope["path"] in AUTH_PATHS
        limit = self.auth_per_minute if is_auth else self.per_minute
        if limit <= 0:
            return await self.app(scope, receive, send)
        now = time.time()
        client = (scope.get("client") or ("inconnu", 0))[0]
        try:
            hits = await self.counter.hit(("auth:" if is_auth else "api:") + client, int(now // 60))
        except Exception:  # disponibilité d'abord : un compteur en panne ne coupe pas l'API
            log.exception("Limiteur de débit indisponible, requête laissée passer")
            hits = 0
        if hits > limit:
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
        for table, (ddl, columns, extra) in SCHEMA.items():
            conn.execute(ddl)
            existing = {row[1] for row in conn.execute(f"PRAGMA table_info({_q(table)})")}
            for column, sql_type in columns:
                if column not in existing:
                    conn.execute(f"ALTER TABLE {_q(table)} ADD COLUMN {_q(column)} {sql_type}")
                    log.info("Colonne ajoutée : %s.%s", table, column)
            for statement in extra:
                conn.execute(statement)


def get_db() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
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


def _scope(owner: Optional[int]) -> tuple:
    """Filtre propriétaire : None = pas de filtre (admin ou ressource non privée)."""
    return ("", []) if owner is None else (" AND owner_id = ?", [owner])


def _fetch_one(db: sqlite3.Connection, table: str, item_id: int, owner: Optional[int] = None) -> dict:
    clause, params = _scope(owner)
    row = db.execute(f"SELECT * FROM {_q(table)} WHERE id = ?{clause}", [item_id, *params]).fetchone()
    if row is None:  # même réponse qu'une ligne inexistante : pas de fuite d'existence
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{table} #{item_id} introuvable")
    return dict(row)


def _like_pattern(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _list_rows(db, table, columns, text_columns, limit, offset, q, sort, owner=None):
    conditions, params = [], []
    if owner is not None:
        conditions.append("owner_id = ?")
        params.append(owner)
    if q and text_columns:
        conditions.append("(" + " OR ".join(f"{_q(c)} LIKE ? ESCAPE '\\'" for c in text_columns) + ")")
        params.extend([_like_pattern(q)] * len(text_columns))
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
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


def _update(db: sqlite3.Connection, table: str, item_id: int, data: dict, owner: Optional[int] = None) -> dict:
    _fetch_one(db, table, item_id, owner)
    if data:
        assignments = ", ".join(f"{_q(c)} = ?" for c in data)
        try:
            db.execute(f"UPDATE {_q(table)} SET {assignments} WHERE id = ?", [*data.values(), item_id])
        except sqlite3.IntegrityError as exc:
            raise _integrity_error(exc) from None
    return _fetch_one(db, table, item_id)


def _delete(db: sqlite3.Connection, table: str, item_id: int, owner: Optional[int] = None) -> None:
    _fetch_one(db, table, item_id, owner)
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


@dataclass(frozen=True)
class Principal:
    """Identité de l'appelant. user_id=None : service (clé API) ou API sans authentification."""

    user_id: Optional[int]
    is_admin: bool

    def owner_filter(self) -> Optional[int]:
        return None if self.is_admin else self.user_id
'''

API_KEY_BLOCK = r'''
# ── Clés API (accès service, droits administrateur) ──────────────────────────
# Aucune clé n'est écrite dans ce fichier : API_KEYS (liste séparée par des virgules,
# pour permettre la rotation) ou API_KEY doivent être définies dans l'environnement.
API_KEYS = [k.encode("utf-8") for k in _env_list("API_KEYS", os.environ.get("API_KEY", ""))]
if not API_KEYS:
    raise RuntimeError("Aucune clé API configurée : définis API_KEYS (ou API_KEY) dans l'environnement.")
if any(len(k) < 16 for k in API_KEYS):
    raise RuntimeError("Chaque clé API doit faire au moins 16 caractères.")
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False, description="Clé d'accès service")


def _valid_api_key(key: str) -> bool:
    candidate = key.encode("utf-8")
    # compare_digest sur chaque clé : temps constant, pas de court-circuit révélateur
    return any([secrets.compare_digest(candidate, k) for k in API_KEYS])
'''

USERS_BLOCK = r'''
# ── Comptes utilisateurs & JWT ───────────────────────────────────────────────
JWT_SECRET = os.environ.get("JWT_SECRET", "")
if len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET doit être défini dans l'environnement (32 caractères minimum).")
JWT_ALGORITHM = "HS256"
JWT_ISSUER = __ISSUER__
JWT_TTL_MINUTES = _env_int("JWT_TTL_MINUTES", __TTL__)
OPEN_REGISTRATION = _env_bool("OPEN_REGISTRATION", __OPEN__)
PASSWORD_MIN, PASSWORD_MAX = 12, 128
EMAIL_PATTERN = r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$"
_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}
_oauth2 = OAuth2PasswordBearer(tokenUrl="auth/token", auto_error=False)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, dklen=32, **_SCRYPT)
    return "scrypt${n}${r}${p}$".format(**_SCRYPT) + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, digest = stored.split("$")
        expected = base64.b64decode(digest)
        actual = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt),
                                n=int(n), r=int(r), p=int(p), dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return secrets.compare_digest(actual, expected)


_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))  # égalise le temps de réponse si l'e-mail est inconnu


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    email: str = Field(..., max_length=254, pattern=EMAIL_PATTERN)
    password: str = Field(..., min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)


class PasswordChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: str = Field(..., max_length=PASSWORD_MAX)
    new_password: str = Field(..., min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)


class UserOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: int
    email: str
    role: str
    created_at: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


def _create_user(db: sqlite3.Connection, email: str, password: str, role: str = "user") -> dict:
    try:
        cur = db.execute(
            'INSERT INTO "users" (email, password_hash, role, created_at) VALUES (?, ?, ?, ?)',
            (email.lower(), hash_password(password), role, _dt.datetime.now(_dt.timezone.utc).isoformat()),
        )
    except sqlite3.IntegrityError:
        raise HTTPException(status.HTTP_409_CONFLICT, "Un compte existe déjà avec cet e-mail") from None
    return dict(db.execute('SELECT * FROM "users" WHERE id = ?', (cur.lastrowid,)).fetchone())


def _issue_token(user) -> Token:
    now = int(time.time())
    payload = {"sub": str(user["id"]), "ver": user["token_version"], "iss": JWT_ISSUER,
               "iat": now, "exp": now + JWT_TTL_MINUTES * 60, "typ": "access"}
    return Token(access_token=jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM),
                 expires_in=JWT_TTL_MINUTES * 60)


_INVALID_TOKEN = HTTPException(status.HTTP_401_UNAUTHORIZED, "Jeton invalide ou expiré",
                               headers={"WWW-Authenticate": "Bearer"})


def _user_from_token(db: sqlite3.Connection, token: str) -> dict:
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM], issuer=JWT_ISSUER,
                            options={"require": ["exp", "iat", "sub", "iss"]})
        user_id = int(claims["sub"])
    except (jwt.PyJWTError, ValueError, TypeError):
        raise _INVALID_TOKEN from None
    if claims.get("typ") != "access":
        raise _INVALID_TOKEN
    row = db.execute('SELECT * FROM "users" WHERE id = ?', (user_id,)).fetchone()
    # compte supprimé, désactivé, ou jetons révoqués (changement de mot de passe) : refus
    if row is None or not row["is_active"] or row["token_version"] != claims.get("ver"):
        raise _INVALID_TOKEN
    return dict(row)


def current_user(token: Optional[str] = Security(_oauth2), db: sqlite3.Connection = Depends(get_db)) -> dict:
    if not token:
        raise _INVALID_TOKEN
    return _user_from_token(db, token)


def bootstrap_admin() -> None:
    """Crée le compte administrateur initial depuis ADMIN_EMAIL / ADMIN_PASSWORD s'il n'existe pas."""
    email, password = os.environ.get("ADMIN_EMAIL", "").strip().lower(), os.environ.get("ADMIN_PASSWORD", "")
    if not email:
        return
    if not PASSWORD_MIN <= len(password) <= PASSWORD_MAX or not re.match(EMAIL_PATTERN, email):
        raise RuntimeError(f"ADMIN_EMAIL invalide ou ADMIN_PASSWORD hors {PASSWORD_MIN}-{PASSWORD_MAX} caractères")
    with sqlite3.connect(DB_PATH, timeout=10) as conn:
        conn.row_factory = sqlite3.Row
        if conn.execute('SELECT 1 FROM "users" WHERE email = ?', (email,)).fetchone() is None:
            _create_user(conn, email, password, "admin")
            log.info("Compte administrateur créé : %s", email)


router_auth = APIRouter(prefix="/auth", tags=["auth"])


@router_auth.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED, summary="Créer un compte")
def register(payload: UserCreate, db: sqlite3.Connection = Depends(get_db)):
    if not OPEN_REGISTRATION:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Les inscriptions sont fermées")
    return _create_user(db, payload.email, payload.password)


@router_auth.post("/token", response_model=Token, summary="Se connecter (OAuth2 mot de passe)")
def login(form: OAuth2PasswordRequestForm = Depends(), db: sqlite3.Connection = Depends(get_db)):
    email, password = form.username.strip().lower()[:254], form.password
    row = db.execute('SELECT * FROM "users" WHERE email = ?', (email,)).fetchone()
    # on vérifie toujours un hash (réel ou factice) : même durée que l'e-mail existe ou non
    valid = len(password) <= PASSWORD_MAX and verify_password(password, row["password_hash"] if row else _DUMMY_HASH)
    if row is None or not valid or not row["is_active"]:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Identifiants invalides", headers={"WWW-Authenticate": "Bearer"})
    return _issue_token(row)


@router_auth.get("/me", response_model=UserOut, summary="Mon compte")
def me(user: dict = Depends(current_user)):
    return user


@router_auth.post("/password", status_code=status.HTTP_204_NO_CONTENT, summary="Changer de mot de passe")
def change_password(payload: PasswordChange, user: dict = Depends(current_user),
                    db: sqlite3.Connection = Depends(get_db)):
    if not verify_password(payload.current_password, user["password_hash"]):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Mot de passe actuel incorrect")
    db.execute('UPDATE "users" SET password_hash = ?, token_version = token_version + 1 WHERE id = ?',
               (hash_password(payload.new_password), user["id"]))  # révoque tous les jetons émis
    return Response(status_code=status.HTTP_204_NO_CONTENT)
'''

USERS_DDL = (
    'CREATE TABLE IF NOT EXISTS "users" (id INTEGER PRIMARY KEY AUTOINCREMENT, '
    "email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, "
    "role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')), "
    "is_active INTEGER NOT NULL DEFAULT 1, token_version INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)"
)


def _principal_block(p: Project) -> str:
    """Dépendance unique d'identification, selon les mécanismes activés."""
    key, users = p.api_key_enabled, p.users_enabled
    L = ["", "# ── Identification de l'appelant " + "─" * 41]
    if not key and not users:
        L += [
            "def get_principal() -> Principal:",
            '    """Aucune authentification configurée : tout appelant a tous les droits."""',
            "    return Principal(None, True)",
        ]
    else:
        params = []
        if key:
            params.append("    api_key: Optional[str] = Security(_api_key_header),")
        if users:
            params.append("    token: Optional[str] = Security(_oauth2),")
            params.append("    db: sqlite3.Connection = Depends(get_db),")
        L += ["def get_principal(", *params, ") -> Principal:"]
        if key:
            L += [
                "    if api_key is not None:",
                "        if not _valid_api_key(api_key):",
                '            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Clé API invalide")',
                "        return Principal(None, True)",
            ]
        if users:
            L += [
                "    if token:",
                "        user = _user_from_token(db, token)",
                '        return Principal(user["id"], user["role"] == "admin")',
            ]
        L += [
            '    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentification requise",',
            '                        headers={"WWW-Authenticate": "Bearer"})',
        ]
    L += [
        "",
        "",
        "def require_admin(principal: Principal = Depends(get_principal)) -> Principal:",
        "    if not principal.is_admin:",
        '        raise HTTPException(status.HTTP_403_FORBIDDEN, "Droits administrateur requis")',
        "    return principal",
        "",
    ]
    return "\n".join(L)


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


def _schema_entry(p: Project, r: Resource) -> str:
    cols = ["id INTEGER PRIMARY KEY AUTOINCREMENT", *(_sql_column(f) for f in r.fields)]
    columns = [(f.name, FIELD_TYPES[f.type][1]) for f in r.fields]
    extra: list[str] = []
    if is_owned(p, r):
        cols.append(f'"owner_id" {OWNER_DDL}')
        columns.append(("owner_id", OWNER_DDL))
        extra.append(f'CREATE INDEX IF NOT EXISTS "ix_{r.name}_owner" ON "{r.name}" ("owner_id")')
    ddl = f'CREATE TABLE IF NOT EXISTS "{r.name}" ({", ".join(cols)})'
    return f"    {r.name!r}: ({ddl!r}, {columns!r}, {extra!r}),"


def _default_literal(field) -> str | None:
    value = coerce_default(field)
    if value is None:
        return None
    if isinstance(value, _dt.datetime):
        return f"_dt.datetime.fromisoformat({value.isoformat()!r})"
    if isinstance(value, _dt.date):
        return f"_dt.date.fromisoformat({value.isoformat()!r})"
    return repr(value)


def _constraints(field) -> list[str]:
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
    kw = _constraints(field)
    if kw:
        return f"    {field.name}: {annotation} = Field({default if default is not None else '...'}, {', '.join(kw)})"
    if default is None:
        return f"    {field.name}: {annotation}"
    return f"    {field.name}: {annotation} = {default}"


STRICT = '    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)'


def _resource_block(p: Project, r: Resource) -> str:
    c, n = r.class_name, r.name
    up = n.upper()
    fields = r.fields
    owned = is_owned(p, r)
    required = [f.name for f in fields if f.required]
    text_cols = tuple(f.name for f in fields if f.type == "str")

    # Dépendances d'accès selon le mode de la ressource
    reader = "" if r.access == "public" else "principal: Principal = Depends(get_principal), "
    writer_dep = "require_admin" if r.access in ("readonly", "public") else "get_principal"
    writer = f"principal: Principal = Depends({writer_dep}), "
    owner_arg = ", principal.owner_filter()" if owned else ""
    owner_kw = ", owner=principal.owner_filter()" if owned else ""

    L: list[str] = [
        f"# ── Ressource : {n} ({r.access}) {'─' * max(0, 46 - len(n) - len(r.access))}",
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
        *(["    owner_id: Optional[int] = None"] if owned else []),
        "",
        "",
        f"{up}_TABLE = {n!r}",
        f"{up}_COLUMNS = {tuple(f.name for f in fields)!r}",
        f"{up}_TEXT_COLUMNS = {text_cols!r}",
        f"router_{n} = APIRouter(prefix={r.route_prefix!r}, tags=[{n!r}])",
        "",
    ]
    if r.ops.get("list"):
        L += [
            "",
            f'@router_{n}.get("", response_model=list[{c}Out], summary={("Lister " + n)!r})',
            f"def list_{n}(",
            "    response: Response,",
            *([f"    {reader.strip()}"] if reader else []),
            "    limit: int = Query(50, ge=1, le=500),",
            "    offset: int = Query(0, ge=0, le=1_000_000),",
            '    q: Optional[str] = Query(None, max_length=100, description="Recherche plein texte sur les champs texte"),',
            "    sort: Optional[str] = Query(None, max_length=64, pattern=r\"^-?[a-z][a-z0-9_]*$\",",
            "                                description=\"Champ de tri, préfixé de '-' pour l'ordre décroissant\"),",
            "    db: sqlite3.Connection = Depends(get_db),",
            "):",
            f"    rows, total = _list_rows(db, {up}_TABLE, {up}_COLUMNS, {up}_TEXT_COLUMNS, limit, offset, q, sort{owner_kw})",
            '    response.headers["X-Total-Count"] = str(total)',
            "    return rows",
            "",
        ]
    if r.ops.get("get"):
        L += [
            "",
            f'@router_{n}.get("/{{item_id}}", response_model={c}Out, summary={("Lire " + n)!r})',
            f"def get_{n}(item_id: ItemId, {reader}db: sqlite3.Connection = Depends(get_db)):",
            f"    return _fetch_one(db, {up}_TABLE, item_id{owner_arg})",
            "",
        ]
    if r.ops.get("create"):
        data = 'payload.model_dump(mode="json")'
        if owned:
            data = f'{{**{data}, "owner_id": principal.user_id}}'
        L += [
            "",
            f'@router_{n}.post("", response_model={c}Out, status_code=status.HTTP_201_CREATED, summary={("Créer " + n)!r})',
            f"def create_{n}(payload: {c}Create, {writer}db: sqlite3.Connection = Depends(get_db)):",
            f"    return _insert(db, {up}_TABLE, {data})",
            "",
        ]
    if r.ops.get("update"):
        L += [
            "",
            f'@router_{n}.put("/{{item_id}}", response_model={c}Out, summary={("Remplacer " + n)!r})',
            f"def replace_{n}(item_id: ItemId, payload: {c}Create, {writer}db: sqlite3.Connection = Depends(get_db)):",
            f'    return _update(db, {up}_TABLE, item_id, payload.model_dump(mode="json"){owner_arg})',
            "",
            "",
            f'@router_{n}.patch("/{{item_id}}", response_model={c}Out, summary={("Modifier partiellement " + n)!r})',
            f"def patch_{n}(item_id: ItemId, payload: {c}Update, {writer}db: sqlite3.Connection = Depends(get_db)):",
            f'    return _update(db, {up}_TABLE, item_id, payload.model_dump(mode="json", exclude_unset=True){owner_arg})',
            "",
        ]
    if r.ops.get("delete"):
        L += [
            "",
            f'@router_{n}.delete("/{{item_id}}", status_code=status.HTTP_204_NO_CONTENT, summary={("Supprimer " + n)!r})',
            f"def delete_{n}(item_id: ItemId, {writer}db: sqlite3.Connection = Depends(get_db)):",
            f"    _delete(db, {up}_TABLE, item_id{owner_arg})",
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
    if p.users_enabled:
        methods.add("POST")
    for r in p.resources:
        if r.ops.get("create"):
            methods.add("POST")
        if r.ops.get("update"):
            methods |= {"PUT", "PATCH"}
        if r.ops.get("delete"):
            methods.add("DELETE")
    methods |= {e.method for e in p.endpoints}
    return sorted(methods)


def _allowed_headers(p: Project) -> list[str]:
    headers = ["Content-Type"]
    if p.api_key_enabled:
        headers.append("X-API-Key")
    if p.users_enabled:
        headers.append("Authorization")
    return headers


def generate_main(p: Project) -> str:
    issues = validate(p)
    if issues:
        raise GenerationError(issues)

    title = _comment(p.name).replace("\\", "/").replace('"', "'")
    imports = [
        "import base64" if p.users_enabled else None,
        "import datetime as _dt",
        "import hashlib" if p.users_enabled else None,
        "import json",
        "import logging",
        "import os",
        "import re" if p.users_enabled else None,
        "import secrets",
        "import sqlite3",
        "import threading",
        "import time",
        "from contextlib import asynccontextmanager",
        "from dataclasses import dataclass",
        "from typing import Annotated, Iterator, Optional",
        "",
        "import anyio",
        "import jwt" if p.users_enabled else None,
        "from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Response, Security, status",
        "from fastapi import Path as PathParam",
        "from fastapi.middleware.cors import CORSMiddleware",
        "from fastapi.middleware.trustedhost import TrustedHostMiddleware",
        "from fastapi.security import APIKeyHeader" if p.api_key_enabled else None,
        "from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm" if p.users_enabled else None,
        "from pydantic import BaseModel, ConfigDict, Field, field_validator",
    ]
    schema = [f"    'users': ({USERS_DDL!r}, [], []),"] if p.users_enabled else []
    schema += [_schema_entry(p, r) for r in p.resources]

    out: list[str] = [
        f'"""{title} — API générée par APIForge {GENERATOR_VERSION}.',
        "",
        "Lancer :  uvicorn main:app --no-server-header",
        "Docs   :  http://127.0.0.1:%d/docs  (DOCS_ENABLED=0 pour les masquer)" % int(p.port),
        "Config :  variables d'environnement, voir .env.example et SECURITY.md",
        '"""',
        *(line for line in imports if line is not None),
        "",
        f"SQLITE_INT_MAX = {SQLITE_INT_MAX}",
        f"DEFAULT_MAX_BODY_BYTES = {int(p.max_body_kb) * 1024}",
        f"DEFAULT_RATE_LIMIT = {int(p.rate_limit)}",
        f"DEFAULT_DOCS = {bool(p.docs_enabled)!r}",
        f"DEFAULT_CORS_ORIGINS = {(p.cors_origins.strip() if p.cors else '')!r}",
        "",
        "# table -> (DDL, colonnes pour la migration, instructions complémentaires)",
        "SCHEMA: dict = {",
        *schema,
        "}",
        RUNTIME,
    ]
    if p.api_key_enabled:
        out.append(API_KEY_BLOCK)
    if p.users_enabled:
        out.append(USERS_BLOCK.replace("__ISSUER__", repr(p.slug))
                   .replace("__TTL__", str(int(p.jwt_ttl_minutes)))
                   .replace("__OPEN__", repr(bool(p.open_registration))))
    out.append(_principal_block(p))

    for r in p.resources:
        out.append("\n" + _resource_block(p, r))

    if p.endpoints:
        out.append("\n# ── Endpoints personnalisés " + "─" * 46)
        out.append("router_custom = APIRouter(dependencies=[Depends(get_principal)])")
        for i, e in enumerate(p.endpoints):
            out.append(_endpoint_block(i, e))

    out += [
        "",
        "# ── Application " + "─" * 57,
        "@asynccontextmanager",
        "async def lifespan(_app: FastAPI):",
        "    init_db()",
        *(["    bootstrap_admin()"] if p.users_enabled else []),
        "    log.info(",
        '        "Démarrage — docs=%s, débit=%s req/min/IP (%s), corps max=%s o, hôtes=%s, CORS=%s",',
        '        DOCS_ENABLED, RATE_LIMIT_PER_MINUTE or "illimité", RATE_LIMIT_BACKEND, MAX_BODY_BYTES,',
        '        ALLOWED_HOSTS or "tous", CORS_ORIGINS or "aucun",',
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
        "app.add_middleware(RateLimitMiddleware, per_minute=RATE_LIMIT_PER_MINUTE,",
        "                   auth_per_minute=AUTH_RATE_LIMIT_PER_MINUTE)",
        "if ALLOWED_HOSTS:",
        "    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)",
        "if CORS_ORIGINS:",
        "    app.add_middleware(",
        "        CORSMiddleware,",
        "        allow_origins=CORS_ORIGINS,",
        "        allow_credentials=False,  # authentification par en-tête, jamais par cookie",
        f"        allow_methods={_used_methods(p)!r},",
        f"        allow_headers={_allowed_headers(p)!r},",
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
    if p.users_enabled:
        out.append("app.include_router(router_auth)")
    out += [f"app.include_router(router_{r.name})" for r in p.resources]
    if p.endpoints:
        out.append("app.include_router(router_custom)")
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


ACCESS_DOC = {
    "owner": "privée : chaque utilisateur ne voit et ne modifie que ses lignes (404 sinon), les admins voient tout",
    "shared": "partagée : tout utilisateur authentifié lit et écrit",
    "readonly": "lecture pour les utilisateurs authentifiés, écriture réservée aux admins",
    "public": "lecture anonyme, écriture réservée aux admins",
}


def _security_md(p: Project) -> str:
    any_auth = p.api_key_enabled or p.users_enabled
    lines = ["# Sécurité\n", "## Authentification\n"]
    if p.users_enabled:
        lines.append(
            "- **Comptes utilisateurs** : `POST /auth/token` (formulaire OAuth2 `username`/`password`) renvoie un\n"
            "  JWT HS256 à passer en `Authorization: Bearer …`. Mots de passe hachés en **scrypt** (sel aléatoire),\n"
            "  12 à 128 caractères. Réponse identique et durée constante que l'e-mail existe ou non.\n"
            "- Jetons signés avec `JWT_SECRET` (obligatoire, 32 caractères min.), émetteur vérifié, expiration\n"
            f"  `JWT_TTL_MINUTES` ({p.jwt_ttl_minutes} min). `POST /auth/password` révoque tous les jetons existants ;\n"
            "  un compte désactivé (`is_active = 0`) est refusé immédiatement.\n"
            f"- Inscription libre via `POST /auth/register` : **{'ouverte' if p.open_registration else 'fermée'}** "
            "(`OPEN_REGISTRATION`).\n"
            "- Premier administrateur créé au démarrage depuis `ADMIN_EMAIL` / `ADMIN_PASSWORD`.\n"
        )
    if p.api_key_enabled:
        lines.append(
            "- **Clés API** (`X-API-Key`) : accès service avec droits administrateur. Lues dans `API_KEYS`\n"
            "  (plusieurs clés = rotation sans coupure), jamais écrites dans le code.\n"
        )
    if not any_auth:
        lines.append("- ⚠️ **Aucune authentification** : n'expose pas cette API sur Internet sans en ajouter une.\n")
    lines.append("\nL'API **refuse de démarrer** si un secret requis manque.\n")
    if p.resources:
        lines.append("\n## Accès par ressource\n\n| Ressource | Règle |\n|---|---|\n")
        for r in p.resources:
            mode = r.access if (p.users_enabled or r.access != "owner") else "shared"
            rule = ACCESS_DOC[mode] if any_auth or mode == "public" else "accès libre (aucune authentification)"
            lines.append(f"| `{r.route_prefix}` | {rule} |\n")
    lines.append(
        "\n## Mesures intégrées\n\n"
        "- Schémas stricts : champs inconnus refusés (422), textes bornés, entiers 64 bits, décimaux sans\n"
        "  NaN/Infini, champs requis non nullables et non vides en PATCH ; `owner_id` jamais modifiable par le client.\n"
        "- SQL paramétré, identifiants validés à la génération, tri sur liste blanche, `LIKE` échappé,\n"
        "  clés étrangères actives (suppression d'un compte = suppression de ses données privées).\n"
        "- Erreurs de contrainte traduites (409/422) sans fuite du SQL ni du schéma.\n"
        "- En-têtes : `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, CSP `default-src 'none'`,\n"
        "  `Cache-Control: no-store`, en-tête `Server` supprimé, HSTS optionnel.\n"
        "- Limite de taille du corps (413). Limitation de débit par IP (429 + `Retry-After`), plus stricte sur\n"
        "  les routes d'authentification, **partagée entre workers** (SQLite) ou **entre machines** (Redis).\n"
        "- CORS restreint aux méthodes et en-têtes utilisés, sans cookies.\n"
        "- Conteneur non-root, healthcheck, base SQLite dans un volume.\n\n"
        "## Variables d'environnement\n\n| Variable | Défaut | Rôle |\n|---|---|---|\n"
    )
    if p.api_key_enabled:
        lines.append("| `API_KEYS` | *(obligatoire)* | Clés service, séparées par des virgules (16 car. min.) |\n")
    if p.users_enabled:
        lines += [
            "| `JWT_SECRET` | *(obligatoire)* | Secret de signature des jetons (32 car. min.) |\n",
            f"| `JWT_TTL_MINUTES` | `{p.jwt_ttl_minutes}` | Durée de validité des jetons |\n",
            f"| `OPEN_REGISTRATION` | `{int(p.open_registration)}` | Inscriptions libres |\n",
            "| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | *(vide)* | Compte admin créé au démarrage s'il n'existe pas |\n",
            "| `AUTH_RATE_LIMIT_PER_MINUTE` | `10` | Tentatives de connexion/inscription par minute et par IP |\n",
        ]
    lines += [
        f"| `CORS_ORIGINS` | `{p.cors_origins if p.cors else ''}` | Origines autorisées (vide = CORS désactivé) |\n",
        "| `ALLOWED_HOSTS` | *(vide = tous)* | Valeurs acceptées pour l'en-tête `Host` |\n",
        f"| `RATE_LIMIT_PER_MINUTE` | `{p.rate_limit}` | Requêtes par minute et par IP (`0` = désactivé) |\n",
        "| `RATE_LIMIT_BACKEND` | `sqlite` | `sqlite` (workers d'une machine), `redis` (plusieurs machines), `memory` (dev) |\n",
        "| `REDIS_URL` | *(vide)* | Requis si `RATE_LIMIT_BACKEND=redis`, ex. `redis://redis:6379/0` |\n",
        f"| `MAX_BODY_BYTES` | `{p.max_body_kb * 1024}` | Taille maximale d'un corps de requête |\n",
        f"| `DOCS_ENABLED` | `{int(p.docs_enabled)}` | Swagger / ReDoc / OpenAPI |\n",
        "| `HSTS` | `0` | Active `Strict-Transport-Security` (seulement derrière HTTPS) |\n",
        "| `APIFORGE_DB` | `./data.db` | Chemin de la base SQLite |\n\n",
        "## Avant la mise en production\n\n"
        "1. Servir l'API derrière un reverse proxy **HTTPS**, puis `HSTS=1`.\n"
        "2. Remplacer `CORS_ORIGINS=*` par la liste exacte des front-ends, renseigner `ALLOWED_HOSTS`.\n"
        "3. `DOCS_ENABLED=0` si la documentation ne doit pas être publique.\n"
        "4. Derrière un proxy, définir `FORWARDED_ALLOW_IPS` (uvicorn) à l'IP du proxy pour que la limitation\n"
        "   de débit voie la vraie IP cliente.\n"
        "5. Plusieurs workers sur une machine : le défaut `sqlite` suffit. Plusieurs machines : `RATE_LIMIT_BACKEND=redis`.\n"
        "6. Générer les secrets avec `python -c \"import secrets; print(secrets.token_urlsafe(48))\"`,\n"
        "   ne jamais committer `.env` ni `data.db`, sauvegarder le volume `/data`.\n",
    ]
    return "".join(lines)


def _requirements(p: Project) -> str:
    reqs = ["fastapi>=0.110,<1.0", "uvicorn[standard]>=0.29,<1.0", "pydantic>=2.5,<3.0"]
    if p.users_enabled:
        reqs += ["pyjwt>=2.8,<3.0", "python-multipart>=0.0.9"]
    reqs.append("# redis>=5.0  # à décommenter si RATE_LIMIT_BACKEND=redis")
    return "\n".join(reqs) + "\n"


def _env_example(p: Project) -> str:
    gen = '# Générer : python -c "import secrets; print(secrets.token_urlsafe(48))"\n'
    out = ""
    if p.api_key_enabled or p.users_enabled:
        out += gen
    if p.api_key_enabled:
        out += "API_KEYS=remplace-moi-par-une-cle-aleatoire\n"
    if p.users_enabled:
        out += ("JWT_SECRET=remplace-moi-par-un-secret-aleatoire-de-48-caracteres\n"
                f"JWT_TTL_MINUTES={p.jwt_ttl_minutes}\n"
                f"OPEN_REGISTRATION={int(p.open_registration)}\n"
                "ADMIN_EMAIL=admin@exemple.fr\nADMIN_PASSWORD=remplace-moi-12-caracteres-min\n"
                "AUTH_RATE_LIMIT_PER_MINUTE=10\n")
    return out + (
        f"CORS_ORIGINS={p.cors_origins if p.cors else ''}\n"
        "ALLOWED_HOSTS=\n"
        f"RATE_LIMIT_PER_MINUTE={p.rate_limit}\n"
        "RATE_LIMIT_BACKEND=sqlite\n"
        "REDIS_URL=\n"
        f"MAX_BODY_BYTES={p.max_body_kb * 1024}\n"
        f"DOCS_ENABLED={int(p.docs_enabled)}\n"
        "HSTS=0\n"
        "APIFORGE_DB=./data.db\n"
    )


def generate_files(p: Project) -> dict[str, str]:
    """Tous les fichiers du projet exporté, nom -> contenu."""
    main = generate_main(p)
    port = int(p.port)
    routes = "\n".join(f"| `{r.method}` | `{r.path}` | {r.summary} |" for r in iter_routes(p))
    run_env = ""
    if p.api_key_enabled:
        run_env += "export API_KEYS=$(python -c 'import secrets; print(secrets.token_urlsafe(48))')\n"
    if p.users_enabled:
        run_env += ("export JWT_SECRET=$(python -c 'import secrets; print(secrets.token_urlsafe(48))')\n"
                    "export ADMIN_EMAIL=admin@exemple.fr ADMIN_PASSWORD='un-mot-de-passe-long'\n")
    auth_note = []
    if p.users_enabled:
        auth_note.append("Connexion : `POST /auth/token` (OAuth2 mot de passe) puis `Authorization: Bearer <jeton>`.")
    if p.api_key_enabled:
        auth_note.append("Accès service : en-tête `X-API-Key`.")
    auth_text = "\n".join(auth_note) or "Aucune authentification n'est activée."
    return {
        "main.py": main,
        "requirements.txt": _requirements(p),
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
            f'CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "{port}", "--workers", "2", '
            '"--no-server-header", "--proxy-headers"]\n'
        ),
        ".dockerignore": ".env\n*.db\n*.db-*\n__pycache__/\n.venv/\n.git/\n",
        ".gitignore": ".env\n*.db\n*.db-shm\n*.db-wal\n__pycache__/\n.venv/\n",
        ".env.example": _env_example(p),
        "SECURITY.md": _security_md(p),
        "README.md": (
            f"# {_comment(p.name)}\n\n{p.description}\n\n"
            "## Démarrage\n\n```bash\npython -m venv .venv && source .venv/bin/activate\n"
            f"pip install -r requirements.txt\n{run_env}uvicorn main:app --reload --no-server-header\n```\n\n"
            f"Documentation interactive : http://127.0.0.1:{port}/docs\n\n"
            "## Docker\n\n```bash\ncp .env.example .env   # puis renseigne les secrets\n"
            f"docker build -t {p.slug} .\n"
            f"docker run -p {port}:{port} --env-file .env -v {p.slug}-data:/data {p.slug}\n```\n\n"
            f"## Sécurité\n\n{auth_text}\n\nRègles d'accès, variables et checklist de production : "
            "[SECURITY.md](SECURITY.md).\n\n"
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
    if p.users_enabled:
        routes += [
            Route("POST", "/auth/register", "Créer un compte"),
            Route("POST", "/auth/token", "Se connecter"),
            Route("GET", "/auth/me", "Mon compte"),
            Route("POST", "/auth/password", "Changer de mot de passe"),
        ]
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
