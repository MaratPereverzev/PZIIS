#!/usr/bin/env bash
# Запуск стенда лабораторной работы №2.1.
#
# Скрипт создаёт .env со случайными секретами (если его ещё нет),
# выпускает самоподписанный сертификат для демонстрации и поднимает
# композицию из трёх контейнеров.
#
# Секреты генерируются локально и в репозиторий не попадают: .env и
# deploy/tls перечислены в .gitignore.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

ENV_FILE=.env
TLS_DIR=deploy/tls

rand() { openssl rand -base64 24 | tr -d '\n/+=' | cut -c1-24; }

if [[ ! -f "$ENV_FILE" ]]; then
    echo "==> генерация $ENV_FILE"
    {
        echo "# Файл создан run.sh. Хранить вне репозитория."
        echo "POSTGRES_PASSWORD=$(rand)"
        echo "VAULT_DB_PASSWORD=$(rand)"
        echo "LAB1_ADMIN_PASSWORD=$(rand)"
        echo "LAB1_USER_PASSWORD=$(rand)"
        echo "LAB1_GUEST_PASSWORD=$(rand)"
        # Мастер-ключ: 32 байта из криптографического генератора.
        echo "VAULT_MASTER_KEY=$(openssl rand -base64 32)"
        echo "VAULT_ADMIN_LOGIN=admin_sys"
        echo "VAULT_ADMIN_PASSWORD=$(rand)Aa1"
    } > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    echo "    пароль администратора приложения:"
    grep VAULT_ADMIN_PASSWORD "$ENV_FILE"
fi

if [[ ! -f "$TLS_DIR/server.crt" ]]; then
    echo "==> выпуск самоподписанного сертификата (только для демонстрации)"
    mkdir -p "$TLS_DIR"
    openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
        -keyout "$TLS_DIR/server.key" -out "$TLS_DIR/server.crt" \
        -subj "/CN=pziis-vault.local" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
    chmod 600 "$TLS_DIR/server.key"
    echo "    ВНИМАНИЕ: сертификат самоподписанный. Защита от атаки"
    echo "    «человек посередине» неполна, пока сертификат не выпущен"
    echo "    доверенным удостоверяющим центром. Для стенда - допустимо."
fi

echo "==> сборка и запуск"
docker compose up --build -d

echo
echo "Приложение: https://127.0.0.1:8443/  (сертификат самоподписанный)"
echo "Логин администратора: $(grep VAULT_ADMIN_LOGIN .env | cut -d= -f2)"
echo "Пароль:               $(grep VAULT_ADMIN_PASSWORD .env | cut -d= -f2)"
echo
echo "Проверки защищённости:  ./check.sh"
echo "Остановить и удалить:   docker compose down -v"
