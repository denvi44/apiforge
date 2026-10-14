# APIForge

Concevoir une API REST à la souris, la lancer, la tester, l'exporter. Interface **Material Design 3** (Flet / Flutter), code généré **FastAPI + Pydantic v2 + SQLite**, sans dépendance au générateur.

## Démarrage

```bash
python -m venv .venv
# Windows : .venv\Scripts\activate   —   Linux/macOS : source .venv/bin/activate
pip install -r requirements.txt
python app.py          # application de bureau
python app.py --web    # dans le navigateur
```

Python 3.10+. Au premier lancement, un projet d'exemple (« Boutique API ») est chargé ; le projet courant est ensuite sauvegardé automatiquement dans `~/.apiforge/`.

## Fonctionnalités

| Onglet | Rôle |
|---|---|
| **Projet** | Nom, version, description, port, CORS, comptes utilisateurs (JWT), clés API service, limites de débit et de taille |
| **Ressources** | Tables + routes CRUD : champs typés, requis, unique, défaut, longueur max ; opérations activables une à une ; mode d'accès (privé, partagé, lecture seule, public) |
| **Endpoints** | Routes libres à réponse JSON fixe (mocks, `/version`, webhooks) ; les `{param}` du chemin sont injectés dans la réponse ; modèles prêts à l'emploi |
| **Code** | Aperçu coloré de `main.py`, `requirements.txt`, `Dockerfile`, `README.md`, `.env.example` ; copie et export |
| **Serveur** | Lancement uvicorn en un clic, journaux en direct, Swagger/ReDoc, client HTTP intégré (clé API ajoutée automatiquement), alerte si le projet a changé depuis le démarrage |

Raccourcis : `Ctrl+S` enregistrer · `Ctrl+O` ouvrir · `Ctrl+E` exporter · `Ctrl+1…5` onglets.

### API générée

- `GET /ressources` avec `limit`, `offset`, `q` (recherche texte), `sort` (`-champ` = décroissant)
- `POST` → 201 · `GET /{id}` → 404 si absent · `PUT` complet · `PATCH` partiel · `DELETE` → 204
- Comptes utilisateurs optionnels : `/auth/register`, `/auth/token` (OAuth2, bouton *Authorize* de Swagger), `/auth/me`, `/auth/password` ; mots de passe scrypt, JWT révocables, admin initial via `ADMIN_EMAIL`/`ADMIN_PASSWORD`
- Contrôle d'accès par ressource : données privées par propriétaire (404 pour les autres), partagées, lecture seule ou publiques ; écritures réservées aux admins selon le mode
- Limitation de débit partagée entre workers (SQLite, par défaut) ou entre machines (Redis), plus stricte sur l'authentification
- Doublon `UNIQUE` → 409, champ obligatoire ou validation → 422, clé absente → 401, corps trop gros → 413, débit dépassé → 429
- Migration légère au démarrage : les colonnes ajoutées dans APIForge sont créées dans la base existante
- Configuration par variables d'environnement : `API_KEYS`, `JWT_SECRET`, `OPEN_REGISTRATION`, `RATE_LIMIT_BACKEND`, `REDIS_URL`, `CORS_ORIGINS`, `ALLOWED_HOSTS`, `RATE_LIMIT_PER_MINUTE`, `MAX_BODY_BYTES`, `DOCS_ENABLED`, `HSTS`, `APIFORGE_DB`
- Durcissement par défaut : aucun secret dans le code (refus de démarrer sans `API_KEYS`), schémas stricts et bornés, en-têtes de sécurité, limites de débit et de taille, erreurs SQL non divulguées, conteneur non-root ; l'export inclut un `SECURITY.md` avec la checklist de production

## Architecture

```
app.py                     point d'entrée Flet
apiforge/
  model.py                 dataclasses du projet, (dé)sérialisation JSON, validation
  generator.py             génération FastAPI + fichiers d'export, liste des routes
  runner.py                sous-processus uvicorn, client HTTP de test
  ui/
    shell.py               AppBar, NavigationRail, dialogues, fichiers, état serveur
    theme.py               composants M3 partagés, coloration syntaxique (tokenize)
    views/                 project · resources · endpoints · code · server
tests/test_core.py         modèle, validation, génération, API générée de bout en bout
```

Le cœur (`model`, `generator`, `runner`) n'importe pas Flet : il est testable et réutilisable en CLI.

**Sécurité du code généré** : tous les noms (ressources, champs, paramètres) sont validés comme identifiants stricts, les chaînes saisies sont émises via `repr()` et les réponses JSON parsées puis ré-émises comme littéraux Python. Aucune saisie n'est interpolée brute dans le code ou le SQL ; les requêtes utilisent des paramètres liés, le tri est contrôlé par liste blanche.

## Tests

```bash
python -m unittest discover -s tests -v
```

Les tests de bout en bout (CRUD réel via `TestClient`, clé API) s'exécutent si `fastapi` et `httpx` sont installés.

## Limites connues

- Pas de relations entre ressources (clés étrangères) hormis le propriétaire des données privées.
- Pas de gestion des comptes par API (désactivation, rôles) : elle se fait en base (`users.is_active`, `users.role`).
- La migration n'ajoute que des colonnes : renommer ou supprimer un champ demande de supprimer `data.db` (dans `~/.apiforge/run/<projet>/` pour le serveur intégré).
- Le serveur intégré lance `python -m uvicorn` avec l'interpréteur courant : il ne fonctionne pas dans un exécutable empaqueté (`flet pack`) sans Python installé à côté. L'export reste disponible.
