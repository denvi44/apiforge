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


def secured_sample() -> Project:
    p = Project.sample()
    p.api_key_enabled, p.api_key = True, KEY
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
        self.assertTrue(imported <= {"os", "secrets", "sqlite3", "uvicorn", "datetime", "json", "logging", "time"})

    def test_hardening_present(self):
        code = generate_main(secured_sample())
        for marker in ('extra="forbid"', "max_length=255", "allow_inf_nan=False", "ESCAPE", "check_required_not_null",
                       "SecurityHeadersMiddleware", "BodySizeLimitMiddleware", "RateLimitMiddleware",
                       "allow_credentials=False", "journal_mode=WAL", "server_header=False"):
            self.assertIn(marker, code)
        self.assertNotIn("Contrainte violée : {exc}", code)  # plus de fuite du message SQLite brut

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
