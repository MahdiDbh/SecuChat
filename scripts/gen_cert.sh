#!/usr/bin/env bash
# Génère un certificat auto-signé pour les tests sur VM (ne pas utiliser en production).
# Usage : ./scripts/gen_cert.sh [nom-ou-IP]   (défaut : localhost)
#   ./scripts/gen_cert.sh 192.168.56.10   -> le client se connecte avec --host 192.168.56.10
#   ./scripts/gen_cert.sh secuchat.lan    -> le client se connecte avec --host secuchat.lan
set -euo pipefail

CN="${1:-localhost}"

# Une IP doit aller dans le SAN en "IP:", un nom en "DNS:" (sinon la vérification échoue)
if [[ "${CN}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
  SAN="IP:${CN},DNS:localhost,IP:127.0.0.1"
elif [[ "${CN}" =~ ^[A-Za-z0-9.-]+$ ]]; then
  SAN="DNS:${CN},DNS:localhost,IP:127.0.0.1"
else
  echo "Nom ou IP invalide : ${CN}" >&2
  exit 1
fi

mkdir -p certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -nodes -days 365 \
  -keyout certs/server.key -out certs/server.crt \
  -subj "/CN=${CN}" \
  -addext "subjectAltName=${SAN}"
chmod 600 certs/server.key
echo "Certificat généré dans certs/ (CN=${CN}, SAN=${SAN})"
