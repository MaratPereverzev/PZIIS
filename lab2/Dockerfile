FROM python:3.12-slim

# Непривилегированный системный пользователь: приложение не должно
# работать с правами root (CWE-250).
RUN useradd --system --no-create-home --shell /usr/sbin/nologin pziis

WORKDIR /srv

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY tests ./tests

# Код принадлежит root, а исполняется от pziis: процесс не может
# перезаписать собственные исполняемые файлы.
RUN chown -R root:pziis /srv && chmod -R 750 /srv

USER pziis

# Файлы, создаваемые процессом, недоступны посторонним по умолчанию.
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 UMASK=0027

# В композиции порт наружу не публикуется: обратиться к приложению может
# только nginx по внутренней сети. В развёртывании на ВМ (deploy/) uvicorn
# слушает 127.0.0.1 и недостижим извне в принципе.
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--no-server-header", "--forwarded-allow-ips", "*"]
