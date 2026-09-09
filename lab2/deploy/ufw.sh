#!/usr/bin/env bash
# Сетевая политика для развёртывания на виртуальной машине.
# Наружу открыт единственный порт приложения - 443/tcp.
set -euo pipefail

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 443/tcp comment 'pziis-vault via nginx'
# Порт SSH открывается только на время демонстрации и только при
# необходимости удалённого доступа к стенду.
# ufw allow 22/tcp comment 'demo access'
ufw --force enable
ufw status verbose

# Приложение (8000) и PostgreSQL (5432) в правилах отсутствуют намеренно:
# оба слушают только 127.0.0.1 и в сетевой политике не нуждаются.
