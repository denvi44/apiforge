"""Tests du cœur (modèle, validation, génération). Lancer : python -m unittest -v"""
import ast
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apiforge.generator import GenerationError, export_project, generate_files, generate_main, iter_routes  # noqa: E402
from apiforge.model import Endpoint, Field, Project, Resource, validate  # noqa: E402

HAS_FASTAPI = all(importlib.util.find_spec(m) for m in ("fastapi", "httpx"))


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
        p = Project(resources=[Resource("Bad Name", [Field("class"), Field("id"), Field("ok", "int", default="x")])])
        msgs = " ".join(i.message for i in validate(p))
        self.assertIn("nom invalide", msgs)
        self.assertIn("mot réservé", msgs)
        self.assertIn("nom réservé", msgs)
        self.assertIn("valeur par défaut invalide", msgs)

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
            p = Project.sample()
            p.api_key_enabled = auth
            p.api_key = "k" * 32
            p.name = 'Nom "piégé" \\N """ end'
            p.description = "multi\nligne ''' \"\"\""
            p.resources[0].fields[0].description = "desc\n'\"`"
            ast.parse(generate_main(p))

    def test_injection_attempts_are_inert(self):
        p = Project.sample()
        p.endpoints[0].response = '{"a": "\\"); import os; os.system(\\"x\\")#"}'
        code = generate_main(p)
        tree = ast.parse(code)
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "attr", None) == "system"]
        self.assertEqual(calls, [])
        imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        self.assertTrue(imported <= {"os", "secrets", "sqlite3", "uvicorn", "datetime"})

    def test_export_writes_all_files(self):
        with tempfile.TemporaryDirectory() as d:
            target = export_project(Project.sample(), d)
            for name in ("main.py", "requirements.txt", "Dockerfile", "README.md", ".env.example"):
                self.assertTrue((target / name).is_file(), name)
            self.assertEqual(set(generate_files(Project.sample())) - {"main.py"},
                             {"requirements.txt", "Dockerfile", "README.md", ".env.example"})

    def test_routes(self):
        routes = {(r.method, r.path) for r in iter_routes(Project.sample())}
        self.assertIn(("PATCH", "/products/{item_id}"), routes)
        self.assertIn(("GET", "/hello/{name}"), routes)


@unittest.skipUnless(HAS_FASTAPI, "fastapi/httpx non installés")
class GeneratedApiTests(unittest.TestCase):
    """Exécute réellement l'API générée avec le TestClient de FastAPI."""

    def load(self, project: Project):
        tmp = tempfile.mkdtemp()
        os.environ["APIFORGE_DB"] = str(Path(tmp) / "t.db")
        path = Path(tmp) / "gen_main.py"
        path.write_text(generate_main(project), encoding="utf-8")
        spec = importlib.util.spec_from_file_location(f"gen_{id(project)}", path)
        mod = importlib.util.module_from_spec(spec)
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
            self.assertEqual(c.post("/products", json={"title": "Stylo", "price": 2}).status_code, 409)
            self.assertEqual(c.post("/products", json={"price": 2}).status_code, 422)
            c.post("/products", json={"title": "Agenda", "price": 9})
            self.assertEqual([p["title"] for p in c.get("/products?sort=-price").json()], ["Agenda", "Stylo"])
            self.assertEqual(len(c.get("/products?q=sty").json()), 1)
            self.assertEqual(c.get("/products?sort=nope").status_code, 400)
            r = c.patch(f"/products/{item['id']}", json={"price": 3})
            self.assertEqual(r.json()["price"], 3)
            self.assertEqual(r.json()["title"], "Stylo")
            self.assertEqual(c.delete(f"/products/{item['id']}").status_code, 204)
            self.assertEqual(c.get(f"/products/{item['id']}").status_code, 404)
            self.assertEqual(c.get("/hello/Vincent").json(), {"message": "Bonjour Vincent !"})

    def test_api_key(self):
        p = Project.sample()
        p.api_key_enabled, p.api_key = True, "s" * 32
        with self.load(p) as c:
            self.assertEqual(c.get("/health").status_code, 200)
            self.assertEqual(c.get("/products").status_code, 401)
            self.assertEqual(c.get("/products", headers={"X-API-Key": "s" * 32}).status_code, 200)


if __name__ == "__main__":
    unittest.main()
