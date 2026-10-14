"""Tests du cœur (modèle, validation, génération). Lancer : python -m unittest discover -s tests -v"""
import ast
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apiforge.generator import GenerationError, export_project, generate_files, generate_main, iter_routes  # noqa: E402
from apiforge.model import Endpoint, Field, Project, Resource, validate  # noqa: E402

HAS_FASTAPI = all(importlib.util.find_spec(m) for m in ("fastapi", "httpx"))
KEY = "k" * 32


JWT = "j" * 48
ADMIN = {"ADMIN_EMAIL": "admin@exemple.fr", "ADMIN_PASSWORD": "mot-de-passe-admin"}


def secured_sample() -> Project:
    p = Project.sample()
    p.api_key_enabled, p.api_key = True, KEY
    return p


def users_sample(api_key: bool = False) -> Project:
    p = Project.sample()
    p.users_enabled, p.open_registration = True, True
    p.api_key_enabled, p.api_key = api_key, KEY
    p.resources.append(Resource("note", [Field("body", "str")], access="owner"))
    p.resources.append(Resource("tag", [Field("label", "str")], access="readonly"))
    return p


class ModelTests(unittest.TestCase):
    def test_roundtrip(self):
        p = Project.sample()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "p.json"
            p.save(path)
            self.assertEqual(Project.load(path), p)

    def test_sample_is_valid(self):
        self.assertEqual(validate(Project.sample()), [])

    def test_invalid_names_rejected(self):
        p = Project(resources=[Resource("Bad Name", [Field("class"), Field("id"), Field("json"),
                                                     Field("ok", "int", default="x")])])
        msgs = " ".join(i.message for i in validate(p))
        self.assertIn("nom invalide", msgs)
        self.assertIn("mot réservé", msgs)
        self.assertIn("nom réservé", msgs)
        self.assertIn("valeur par défaut invalide", msgs)

    def test_bounds_validation(self):
        p = Project(resources=[Resource("r", [
            Field("a", "int", default=str(2 ** 64)),
            Field("b", "float", default="nan"),
            Field("c", "str", default="x" * 10, max_length=5),
            Field("d", "str", max_length=0),
        ])], rate_limit=-1, max_body_kb=0)
        msgs = " ".join(i.message for i in validate(p))
        for expected in ("hors limites SQLite", "valeur par défaut invalide", "dépasse la longueur",
                         "longueur maximale entre", "limite de requêtes", "taille maximale du corps"):
            self.assertIn(expected, msgs)

    def test_api_key_format(self):
        p = secured_sample()
        p.api_key = "é" * 20
        self.assertIn("ASCII", " ".join(i.message for i in validate(p)))

    def test_endpoint_validation(self):
        p = Project(endpoints=[Endpoint(path="no-slash"), Endpoint(path="/x", response="{bad")])
        msgs = " ".join(i.message for i in validate(p))
        self.assertIn("chemin invalide", msgs)
        self.assertIn("JSON de réponse invalide", msgs)

    def test_unknown_keys_ignored(self):
        d = Project.sample().to_dict()
        d["future_option"] = 1
        d["resources"][0]["fields"][0]["future"] = True
        Project.from_dict(d)


class GeneratorTests(unittest.TestCase):
    def test_refuses_invalid_project(self):
        with self.assertRaises(GenerationError):
            generate_main(Project(name=""))

    def test_generated_code_is_valid_python(self):
        for auth in (False, True):
            p = secured_sample()
            p.api_key_enabled = auth
            p.name = 'Nom "piégé" \\N """ end'
            p.description = "multi\nligne ''' \"\"\""
            p.resources[0].fields[0].description = "desc\n'\"`"
            ast.parse(generate_main(p))

    def test_secret_never_written(self):
        p = secured_sample()
        files = generate_files(p)
        for name, content in files.items():
            self.assertNotIn(KEY, content, name)
        with tempfile.TemporaryDirectory() as d:
            target = export_project(p, d)
            for path in target.iterdir():
                self.assertNotIn(KEY, path.read_text(encoding="utf-8"), path.name)

    def test_injection_attempts_are_inert(self):
        p = Project.sample()
        p.endpoints[0].response = '{"a": "\\"); import os; os.system(\\"x\\")#"}'
        tree = ast.parse(generate_main(p))
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "attr", None) == "system"]
        self.assertEqual(calls, [])
        imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        self.assertTrue(imported <= {"os", "secrets", "sqlite3", "uvicorn", "datetime", "json", "logging", "time",
                                     "threading", "anyio", "base64", "hashlib", "re", "jwt", "redis.asyncio"})

    def test_hardening_present(self):
        code = generate_main(secured_sample())
        for marker in ('extra="forbid"', "max_length=255", "allow_inf_nan=False", "ESCAPE", "check_required_not_null",
                       "SecurityHeadersMiddleware", "BodySizeLimitMiddleware", "RateLimitMiddleware",
                       "allow_credentials=False", "journal_mode=WAL", "server_header=False"):
            self.assertIn(marker, code)
        self.assertNotIn("Contrainte violée : {exc}", code)  # plus de fuite du message SQLite brut

    def test_users_mode_generation(self):
        for api_key in (False, True):
            p = users_sample(api_key)
            files = generate_files(p)
            ast.parse(files["main.py"])
            code = files["main.py"]
            for marker in ("hashlib.scrypt", "OAuth2PasswordBearer", "token_version", "_DUMMY_HASH",
                           "owner_id", "require_admin", "bootstrap_admin", "SqliteCounter", "RedisCounter"):
                self.assertIn(marker, code)
            self.assertIn("pyjwt", files["requirements.txt"])
            self.assertIn("JWT_SECRET", files[".env.example"])
            self.assertNotIn(JWT, code)
            routes = {(r.method, r.path) for r in iter_routes(p)}
            self.assertIn(("POST", "/auth/token"), routes)

    def test_reserved_paths(self):
        p = users_sample()
        p.resources.append(Resource("x", [Field("a")], path="/auth/x"))
        p.endpoints.append(Endpoint(path="/health/deep"))
        msgs = " ".join(i.message for i in validate(p))
        self.assertIn("est réservé", msgs)
        self.assertIn("chemin réservé", msgs)

    def test_export_writes_all_files(self):
        expected = {"main.py", "requirements.txt", "Dockerfile", "README.md", ".env.example",
                    "SECURITY.md", ".gitignore", ".dockerignore"}
        self.assertEqual(set(generate_files(Project.sample())), expected)
        with tempfile.TemporaryDirectory() as d:
            target = export_project(Project.sample(), d)
            for name in expected:
                self.assertTrue((target / name).is_file(), name)
            docker = (target / "Dockerfile").read_text()
            self.assertIn("USER app", docker)
            self.assertIn("HEALTHCHECK", docker)
            self.assertIn(".env", (target / ".gitignore").read_text())

    def test_routes(self):
        routes = {(r.method, r.path) for r in iter_routes(Project.sample())}
        self.assertIn(("PATCH", "/products/{item_id}"), routes)
        self.assertIn(("GET", "/hello/{name}"), routes)


@unittest.skipUnless(HAS_FASTAPI, "fastapi/httpx non installés")
class GeneratedApiTests(unittest.TestCase):
    """Exécute réellement l'API générée avec le TestClient de FastAPI."""

    def load(self, project: Project, **env):
        tmp = tempfile.mkdtemp()
        env = {"APIFORGE_DB": str(Path(tmp) / "t.db"), **env}
        path = Path(tmp) / "gen_main.py"
        path.write_text(generate_main(project), encoding="utf-8")
        spec = importlib.util.spec_from_file_location(f"gen_{id(project)}_{len(env)}", path)
        mod = importlib.util.module_from_spec(spec)
        with mock.patch.dict(os.environ, env):
            spec.loader.exec_module(mod)
        from fastapi.testclient import TestClient
        return TestClient(mod.app)

    def test_crud_cycle(self):
        with self.load(Project.sample()) as c:
            self.assertEqual(c.get("/health").json(), {"status": "ok"})
            r = c.post("/products", json={"title": "Stylo", "price": 1.5, "released": "2024-05-01"})
            self.assertEqual(r.status_code, 201, r.text)
            item = r.json()
            self.assertIs(item["in_stock"], True)
            dup = c.post("/products", json={"title": "Stylo", "price": 2})
            self.assertEqual(dup.status_code, 409)
            self.assertNotIn("constraint", dup.text.lower())
            self.assertEqual(c.post("/products", json={"price": 2}).status_code, 422)
            c.post("/products", json={"title": "Agenda", "price": 9})
            r = c.get("/products?sort=-price")
            self.assertEqual([p["title"] for p in r.json()], ["Agenda", "Stylo"])
            self.assertEqual(r.headers["x-total-count"], "2")
            self.assertEqual(len(c.get("/products?q=sty").json()), 1)
            self.assertEqual(c.get("/products?sort=nope").status_code, 400)
            r = c.patch(f"/products/{item['id']}", json={"price": 3})
            self.assertEqual((r.json()["price"], r.json()["title"]), (3, "Stylo"))
            self.assertEqual(c.delete(f"/products/{item['id']}").status_code, 204)
            self.assertEqual(c.get(f"/products/{item['id']}").status_code, 404)
            self.assertEqual(c.get("/hello/Vincent").json(), {"message": "Bonjour Vincent !"})

    def test_strict_input(self):
        with self.load(Project.sample()) as c:
            ok = {"title": "A", "price": 1}
            self.assertEqual(c.post("/products", json={**ok, "admin": True}).status_code, 422)  # champ inconnu
            self.assertEqual(c.post("/products", json={**ok, "title": "x" * 256}).status_code, 422)
            self.assertEqual(c.post("/products", json={**ok, "title": "   "}).status_code, 422)
            item = c.post("/products", json=ok).json()
            self.assertEqual(c.patch(f"/products/{item['id']}", json={"title": None}).status_code, 422)
            self.assertEqual(c.get(f"/products/{2 ** 64}").status_code, 422)
            self.assertEqual(c.get("/products?sort=title;drop").status_code, 422)
            c.post("/products", json={"title": "100%_pur", "price": 1})
            self.assertEqual([p["title"] for p in c.get("/products", params={"q": "%"}).json()], ["100%_pur"])

    def test_security_headers_and_limits(self):
        with self.load(Project.sample(), RATE_LIMIT_PER_MINUTE="5", MAX_BODY_BYTES="64") as c:
            r = c.get("/products")
            self.assertEqual(r.headers["x-content-type-options"], "nosniff")
            self.assertEqual(r.headers["cache-control"], "no-store")
            self.assertIn("default-src 'none'", r.headers["content-security-policy"])
            big = c.post("/products", content=json.dumps({"title": "x" * 200, "price": 1}),
                         headers={"content-type": "application/json"})
            self.assertEqual(big.status_code, 413)
            codes = [c.get("/products").status_code for _ in range(5)]
            self.assertIn(429, codes)
            self.assertEqual(c.get("/health").status_code, 200)  # healthcheck jamais limité

    def test_docs_can_be_disabled(self):
        with self.load(Project.sample(), DOCS_ENABLED="0") as c:
            self.assertEqual(c.get("/docs").status_code, 404)
            self.assertEqual(c.get("/openapi.json").status_code, 404)

    def login(self, c, email, password):
        r = c.post("/auth/token", data={"username": email, "password": password})
        self.assertEqual(r.status_code, 200, r.text)
        return {"Authorization": f"Bearer {r.json()['access_token']}"}

    def test_users_and_ownership(self):
        with self.load(users_sample(), JWT_SECRET=JWT, **ADMIN) as c:
            # public : lecture anonyme, écriture admin
            self.assertEqual(c.get("/products").status_code, 200)
            self.assertEqual(c.post("/products", json={"title": "A", "price": 1}).status_code, 401)
            self.assertEqual(c.get("/notes").status_code, 401)

            for email in ("alice@exemple.fr", "bob@exemple.fr"):
                self.assertEqual(c.post("/auth/register", json={"email": email, "password": "x" * 12}).status_code, 201)
            self.assertEqual(c.post("/auth/register", json={"email": "ALICE@exemple.fr", "password": "x" * 12}).status_code, 409)
            self.assertEqual(c.post("/auth/register", json={"email": "c@exemple.fr", "password": "court"}).status_code, 422)
            alice = self.login(c, "alice@exemple.fr", "x" * 12)
            bob = self.login(c, "bob@exemple.fr", "x" * 12)
            admin = self.login(c, ADMIN["ADMIN_EMAIL"], ADMIN["ADMIN_PASSWORD"])
            self.assertEqual(c.get("/auth/me", headers=admin).json()["role"], "admin")

            # privé : chacun ses données, 404 pour celles des autres, l'admin voit tout
            note = c.post("/notes", json={"body": "secret"}, headers=alice).json()
            self.assertEqual(c.post("/notes", json={"body": "x", "owner_id": 99}, headers=alice).status_code, 422)
            self.assertEqual(c.get("/notes", headers=bob).json(), [])
            self.assertEqual(c.get(f"/notes/{note['id']}", headers=bob).status_code, 404)
            self.assertEqual(c.patch(f"/notes/{note['id']}", json={"body": "pirate"}, headers=bob).status_code, 404)
            self.assertEqual(c.delete(f"/notes/{note['id']}", headers=bob).status_code, 404)
            self.assertEqual(len(c.get("/notes", headers=alice).json()), 1)
            self.assertEqual(len(c.get("/notes", headers=admin).json()), 1)

            # lecture seule : lecture connectée, écriture admin
            self.assertEqual(c.post("/tags", json={"label": "x"}, headers=alice).status_code, 403)
            self.assertEqual(c.post("/tags", json={"label": "x"}, headers=admin).status_code, 201)
            self.assertEqual(c.get("/tags", headers=bob).status_code, 200)

            # mauvais identifiants : même réponse que l'e-mail existe ou non
            bad = c.post("/auth/token", data={"username": "alice@exemple.fr", "password": "y" * 12})
            unknown = c.post("/auth/token", data={"username": "nobody@exemple.fr", "password": "y" * 12})
            self.assertEqual((bad.status_code, bad.json()), (unknown.status_code, unknown.json()))

            # changement de mot de passe : les anciens jetons sont révoqués
            r = c.post("/auth/password", json={"current_password": "x" * 12, "new_password": "z" * 12}, headers=alice)
            self.assertEqual(r.status_code, 204)
            self.assertEqual(c.get("/auth/me", headers=alice).status_code, 401)
            self.login(c, "alice@exemple.fr", "z" * 12)

            # jeton falsifié ou signé avec un autre secret
            import jwt as pyjwt
            forged = pyjwt.encode({"sub": "1", "ver": 0, "iss": "boutique-api", "iat": 0, "exp": 2 ** 40,
                                   "typ": "access"}, "autre-secret-" * 4, algorithm="HS256")
            self.assertEqual(c.get("/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code, 401)
            none_alg = pyjwt.encode({"sub": "1"}, None, algorithm="none")
            self.assertEqual(c.get("/auth/me", headers={"Authorization": f"Bearer {none_alg}"}).status_code, 401)

    def test_users_require_secret_and_closed_registration(self):
        with self.assertRaises(RuntimeError):
            self.load(users_sample(), JWT_SECRET="trop-court")
        p = users_sample()
        p.open_registration = False
        with self.load(p, JWT_SECRET=JWT) as c:
            self.assertEqual(c.post("/auth/register", json={"email": "a@b.fr", "password": "x" * 12}).status_code, 403)

    def test_rate_limit_shared_between_workers(self):
        """Deux applications (= deux workers) sur la même base partagent le compteur."""
        tmp = tempfile.mkdtemp()
        env = {"APIFORGE_DB": str(Path(tmp) / "shared.db"), "RATE_LIMIT_PER_MINUTE": "4"}
        with self.load(Project.sample(), **env) as w1, self.load(Project.sample(), **env) as w2:
            codes = [w.get("/products").status_code for w in (w1, w2, w1, w2, w1)]
            self.assertEqual(codes[:4], [200] * 4)
            self.assertEqual(codes[4], 429)

    def test_auth_routes_stricter_limit(self):
        with self.load(users_sample(), JWT_SECRET=JWT, AUTH_RATE_LIMIT_PER_MINUTE="3") as c:
            codes = [c.post("/auth/token", data={"username": "a@b.fr", "password": "x" * 12}).status_code
                     for _ in range(4)]
            self.assertEqual(codes, [401, 401, 401, 429])
            self.assertEqual(c.get("/products").status_code, 200)  # le reste de l'API n'est pas affecté

    def test_api_key(self):
        with self.assertRaises(RuntimeError):
            self.load(secured_sample(), API_KEYS="", API_KEY="")
        with self.load(secured_sample(), API_KEYS=f"{KEY},{'z' * 20}") as c:
            self.assertEqual(c.get("/health").status_code, 200)
            self.assertEqual(c.get("/products").status_code, 401)
            self.assertEqual(c.get("/products", headers={"X-API-Key": KEY}).status_code, 200)
            self.assertEqual(c.get("/products", headers={"X-API-Key": "z" * 20}).status_code, 200)


if __name__ == "__main__":
    unittest.main()
