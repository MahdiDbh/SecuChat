# SecuChat — Messagerie multipoints sécurisée

Projet du cours **Secure Development / DevSecOps** — EPITA, Majeure Cybersécurité, 2026-2027.
Version actuelle : **β (MVP)** — rendu du 17/11/2026.

SecuChat est une messagerie client/serveur en Python qui permet à plusieurs utilisateurs d'échanger dans des salons (multipoints) ou en message direct. Les messages sont chiffrés de bout en bout : le serveur relaie des messages qu'il ne peut pas lire.

> ⚠️ À tester uniquement sur nos propres VMs (consigne du cours).

---

## Fonctionnalités (version β)

| Fonctionnalité | État |
|---|---|
| Inscription / connexion avec mot de passe (Argon2id) | ✅ |
| Transport chiffré TLS 1.3 (client ↔ serveur), certificat vérifié par le client | ✅ |
| Salons de discussion multipoints (`/join`, `/leave`) + notifications d'entrée/sortie | ✅ |
| Messages directs entre deux utilisateurs | ✅ |
| Chiffrement de bout en bout (X25519 + XSalsa20-Poly1305, PyNaCl) | ✅ |
| Protection contre le rejeu et le déplacement de messages par le serveur | ✅ |
| Limitation des tentatives de connexion (par compte et par IP) | ✅ |
| Historique des messages chiffrés côté serveur | ⏳ V1 |
| Signature des messages + vérification des empreintes de clés | ⏳ V1 |

## Architecture

```
┌──────────────┐   TLS 1.3 / JSON lines   ┌──────────────────────┐
│  Client CLI  │ ───────────────────────▶ │  Serveur asyncio     │
│  (clé privée │ ◀─────────────────────── │  - auth (Argon2id)   │
│   locale)    │                          │  - salons / routage  │
└──────────────┘                          │  - SQLite (requêtes  │
       ▲                                  │    paramétrées)      │
       │ chiffrement E2E (PyNaCl Box)     └──────────────────────┘
       ▼
┌──────────────┐
│ Autre client │
└──────────────┘
```

Le détail (protocole, analyse STRIDE, mesures de sécurité) est dans le document de spécifications rendu avec le projet.

## Arborescence

```
secuchat/
├── src/secuchat/
│   ├── config.py      # paramètres (ports, limites, chemins)
│   ├── protocol.py    # format des messages + validation (pydantic)
│   ├── db.py          # accès SQLite, requêtes paramétrées uniquement
│   ├── auth.py        # hachage Argon2id, sessions, anti brute-force
│   ├── crypto.py      # clés X25519, chiffrement E2E, stockage chiffré de la clé privée
│   ├── server.py      # serveur TLS asyncio, salons, routage
│   └── client.py      # client en ligne de commande
├── tests/             # tests unitaires et d'intégration (pytest)
├── scripts/gen_cert.sh
├── .github/workflows/ci.yml
├── pyproject.toml
└── requirements.txt
```

## Prérequis

- Python 3.11 ou plus
- OpenSSL (pour générer le certificat de test)
- Linux (testé sur Kali, Ubuntu 24.04 / Debian 12)

## Installation

```bash
git clone <URL_DU_REPO>
cd secuchat
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Lancement

### En local (une seule machine)

```bash
./scripts/gen_cert.sh                     # certificat pour localhost / 127.0.0.1
python -m secuchat.server --cert certs/server.crt --key certs/server.key
```

Dans d'autres terminaux (un par utilisateur) :
```bash
python -m secuchat.client --ca certs/server.crt
```

### Sur les VMs

Sur la VM serveur, générer le certificat **avec l'IP (ou le nom) de la VM** :
```bash
./scripts/gen_cert.sh 192.168.56.10
python -m secuchat.server --host 0.0.0.0 --port 8443 --cert certs/server.crt --key certs/server.key
```

Copier **uniquement** `certs/server.crt` (jamais `server.key`) sur les VMs clientes, puis :
```bash
python -m secuchat.client --host 192.168.56.10 --port 8443 --ca server.crt
```

Le client vérifie que le certificat correspond à l'adresse demandée : si l'adresse ne figure pas dans le certificat, la connexion est refusée (protection contre l'interception). `--server-name <nom>` permet d'indiquer explicitement le nom attendu dans le certificat.

Options utiles : serveur `--db <fichier>` (défaut `~/.secuchat/server.db`), client `--keys-dir <dossier>` (défaut `~/.secuchat/keys`). La variable `SECUCHAT_HOME` change le dossier `~/.secuchat`.

## Commandes du client

| Commande | Effet |
|---|---|
| `/register <user>` | Crée un compte et une paire de clés (mot de passe demandé sans écho, 12 caractères minimum) |
| `/login <user>` | Déverrouille la clé privée locale et se connecte |
| `/join <salon>` | Rejoint un salon (créé s'il n'existe pas) |
| `/leave <salon>` | Quitte un salon |
| `/msg <salon> <texte>` | Envoie un message chiffré à tous les membres du salon |
| `/dm <user> <texte>` | Envoie un message direct chiffré |
| `/users <salon>` | Liste les membres d'un salon (réservé aux membres) |
| `/quit` | Déconnexion |

La clé privée est stockée chiffrée par le mot de passe dans `~/.secuchat/keys/<user>.key` (permissions `600`) : un compte ne peut être utilisé que depuis le poste où il a été créé.

## Tests

```bash
pytest --cov=secuchat --cov-report=term-missing
```

167 tests (unitaires, serveur TLS réel, intégration avec 3 clients), couverture ≈ 84 %.

Vérifications de sécurité locales (identiques à la CI) :
```bash
ruff check .
bandit -r src -ll
pip-audit -r requirements.txt
```

## Qualité et sécurité (CI GitHub Actions)

À chaque push, la pipeline lance :
- `ruff` : style et bonnes pratiques
- `bandit` : analyse statique de sécurité du code Python
- `pip-audit` : vulnérabilités connues dans les dépendances
- `pytest` + couverture
- CodeQL (analyse de code GitHub) et Gitleaks (recherche de secrets)
- génération d'un SBOM CycloneDX

## Limites connues (version β)

- Le serveur connaît les métadonnées (qui parle à qui, dans quel salon, à quel moment).
- Pas encore de vérification des empreintes de clés : un serveur malveillant pourrait substituer une clé publique (prévu en V1).
- Pas de confidentialité persistante (forward secrecy) au niveau E2E.
- Pas d'historique hors ligne : un message n'est remis qu'aux destinataires connectés.
- L'inscription n'est pas encore limitée par IP (la connexion l'est).

## Équipe

| Membre | Rôle |
|---|---|
|Islam Mahdi DEBBAH | Chef de projet, authentification, chiffrement E2E, CI et documentation |
|Yanis Ramy OULAD DAOUD| Protocole, serveur, client CLI |

Les tests sont écrits par les deux membres : chacun teste les modules qu'il développe, et l'autre relit la pull request.

## Licence

Projet académique — EPITA 2026-2027.
