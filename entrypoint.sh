#!/bin/sh
set -e

# Carregar .env se existir (docker-compose já injeta, mas útil para docker run)
if [ -f ./.env ]; then
  export $(grep -v '^#' ./.env | xargs -I {} echo {})
fi

# Checagem básica do Django
python manage.py check --deploy || true

# Migrar banco (SQLite por padrão; sem modelos customizados)
python manage.py migrate --noinput || true

exec gunicorn ad_api.wsgi:application \
  --bind 0.0.0.0:8000 \
  --workers 2 \
  --timeout 60


