#!/usr/bin/env bash
# Génère un certificat auto-signé pour les tests sur VM (ne pas utiliser en production).
set -euo pipefail

CN="${1:-localhost}"
mkdir -p certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -nodes -days 365 \
  -keyout certs/server.key -out certs/server.crt \
  -subj "/CN=${CN}" \
  -addext "subjectAltName=DNS:${CN},DNS:localhost,IP:127.0.0.1"
chmod 600 certs/server.key
echo "Certificat généré dans certs/ (CN=${CN})"
