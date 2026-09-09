#!/usr/bin/env bash
# Автоматические проверки защищённости.
#
# Запускаются в том же образе и от того же непривилегированного
# пользователя, что и приложение, и обращаются к той же СУБД под той же
# сервисной ролью vault_app - иначе проверка привилегий не имела бы смысла.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

[[ -f .env ]] || { echo "Сначала запустите ./run.sh"; exit 1; }

# Лимит попыток входа на адрес поднят: все проверки идут с одного адреса
# и упирались бы в него. Сам лимит проверяется отдельно
# (test_sliding_window_limits), блокировка учётной записи - в
# test_account_lockout_after_repeated_failures.
docker compose run --rm \
    -e VAULT_LOGIN_IP_LIMIT=100000 \
    -e VAULT_FAILED_DELAY_MS=0 \
    app python -m pytest tests -v --tb=short -p no:cacheprovider "$@"
