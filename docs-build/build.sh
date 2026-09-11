#!/usr/bin/env bash
# Пересборка пояснительных документов по всем лабораторным работам.
#
# Правится исходник lab<N>.frag.html, затем запускается этот скрипт:
# он подставляет общий шаблон theme.css, печатает PDF через Chrome
# и приводит номера страниц в оглавлении к фактическим.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
ROOT=..

declare -A TITLES=(
  [1]="Разбор ЛР1 — Управление доступом с помощью ACL"
  [2]="Разбор ЛР2 — Анализ защищённости приложений"
  [3]="Разбор ЛР3 — Анализ безопасности кода"
)

for n in "${!TITLES[@]}"; do
    out="$ROOT/lab$n/docs/ЛР$n — объяснение и ответы.pdf"
    echo "==> ЛР$n"
    python3 fixtoc.py "lab$n.frag.html" "/tmp/lab$n.html" "$out" "${TITLES[$n]}"
done
