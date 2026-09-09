# Одноразовое окружение для лабораторной работы №1 по ПЗИИС.
#
# Берётся чистая ОС, а не образ postgres: часть 2 задания требует программу,
# которая сама УСТАНАВЛИВАЕТ и затем ПОЛНОСТЬЮ УДАЛЯЕТ СУБД. В образе postgres
# сервер уже установлен и датадир проинициализирован, поэтому демонстрировать
# было бы нечего. Часть 1 к PostgreSQL отношения не имеет и требует только
# чистую ОС с useradd/groupadd.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        sudo \
        passwd \
        procps \
        psmisc \
        lsof \
        iproute2 \
        util-linux \
        ca-certificates \
        locales \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /lab
CMD ["/bin/bash"]
