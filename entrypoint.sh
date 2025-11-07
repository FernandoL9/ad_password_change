#!/bin/sh
set -e

# Carregar .env se existir (docker-compose já injeta, mas útil para docker run)
if [ -f ./.env ]; then
  export $(grep -v '^#' ./.env | xargs -I {} echo {})
fi

# Definir porta (padrão 8000, pode ser sobrescrita por variável de ambiente)
PORT=${PORT:-8000}

# Checagem básica do Django
python manage.py check --deploy || true

# Migrar banco (SQLite por padrão; sem modelos customizados)
python manage.py migrate --noinput || true

# Iniciar gunicorn na porta especificada, escutando em todas as interfaces (0.0.0.0)
exec gunicorn ad_api.wsgi:application \
  --bind 0.0.0.0:${PORT} \
  --workers 2 \
  --timeout 60 \
  --access-logfile - \
  --error-logfile -


