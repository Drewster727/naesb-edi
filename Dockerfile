FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends gnupg ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 1000 naesb
WORKDIR /app

COPY pyproject.toml ./
RUN pip install --no-cache-dir .

COPY app ./app
COPY db ./db
COPY config/config.example.yaml config/partners.example.yaml ./config/

RUN mkdir -p /data/gnupg /data/inbound \
 && chown -R naesb:naesb /data /app
USER naesb

ENV NAESB_CONFIG_PATH=/app/config/config.yaml
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
