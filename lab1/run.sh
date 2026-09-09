#!/usr/bin/env bash
# Сборка и запуск одноразового контейнера с лабораторной работой.
#
# Обе программы делают деструктивные вещи на уровне ОС (создают и удаляют
# системных пользователей, вычищают PostgreSQL через apt purge), поэтому
# запускать их на рабочей машине нельзя. Контейнер --rm гарантирует, что
# после выхода от прогона не останется ничего.
set -euo pipefail

IMAGE=pziis-lab1
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker build -t "$IMAGE" "$REPO"

exec docker run --rm -it \
    --hostname pziis-lab1 \
    --cap-add SYS_ADMIN \
    --security-opt apparmor=unconfined \
    -v "$REPO:/lab" \
    -w /lab \
    "$IMAGE" "$@"
