FROM python:3.13.14-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p /app /run/ftp-certs /srv/ftp/sony \
    && chown -R app:app /app /srv/ftp

WORKDIR /app

COPY requirements.txt .
RUN python -m pip install --no-cache-dir --requirement requirements.txt

COPY --chown=app:app server.py .

USER 10001:10001

EXPOSE 2121 30000-30009

ENTRYPOINT ["python", "/app/server.py"]
