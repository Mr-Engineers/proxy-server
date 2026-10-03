FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY app ./app
COPY migrations ./migrations
COPY policies ./policies
COPY seeds ./seeds

# ALB marketplace (two-backend) ma certyfikat z naszego CA (brak publicznej domeny).
# Dokładamy go do publicznych CA (certifi), których dalej potrzebuje Supabase i Bedrock.
COPY certs/backend-2-ca.crt /tmp/backend-2-ca.crt
RUN cat "$(python -c 'import certifi; print(certifi.where())')" /tmp/backend-2-ca.crt > /etc/ssl/ca-bundle.pem \
    && rm /tmp/backend-2-ca.crt
ENV SSL_CERT_FILE=/etc/ssl/ca-bundle.pem

RUN useradd --create-home --uid 1000 appuser
USER appuser

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips", "*"]
