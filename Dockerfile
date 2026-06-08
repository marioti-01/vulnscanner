FROM python:3.12-slim

# System deps — inclui Playwright e WeasyPrint
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev libffi-dev libssl-dev \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 libffi-dev shared-mime-info \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libxcomposite1 \
    libxdamage1 libxfixes3 libxrandr2 libgbm1 \
    libasound2 libpangoft2-1.0-0 fonts-liberation \
    curl wget gnupg2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependências Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Playwright — instala Chromium para crawler SPA
RUN playwright install chromium --with-deps 2>/dev/null || \
    python -m playwright install chromium 2>/dev/null || \
    echo "Playwright chromium install skipped"

# Copia código
COPY . .

# Diretórios de runtime
RUN mkdir -p reports logs static/uploads

# Usuário não-root para segurança
RUN useradd -m -u 1000 vulnscanner && \
    chown -R vulnscanner:vulnscanner /app
USER vulnscanner

EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
