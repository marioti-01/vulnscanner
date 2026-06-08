#!/bin/bash
# VulnScanner v8 — Script de deploy em um comando
# Uso: ./deploy/setup.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "  ╦  ╦┬ ┬┬  ┌┐┌╔═╗┌─┐┌─┐┌┐┌┌┐┌┌─┐┬─┐  ┬  ┬ ┌─┐"
echo "  ╚╗╔╝│ ││  │││╚═╗│  ├─┤││││││├┤ ├┬┘  └┐┌┘ ├┤ "
echo "   ╚╝ └─┘┴─┘┘└┘╚═╝└─┘┴ ┴┘└┘┘└┘└─┘┴└─   └┘  └─┘"
echo -e "${NC}"
echo -e "${GREEN}VulnScanner v8.0 — Deploy Setup${NC}"
echo ""

# Verifica dependências
check_dep() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}✗ $1 não encontrado. Instale antes de continuar.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ $1${NC}"
}

echo "Verificando dependências..."
check_dep docker
check_dep docker-compose

# Cria .env se não existir
if [ ! -f .env ]; then
    echo ""
    echo -e "${YELLOW}Criando .env com valores padrão...${NC}"
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || openssl rand -hex 32)
    DB_PASS=$(python3 -c "import secrets; print(secrets.token_hex(16))" 2>/dev/null || openssl rand -hex 16)
    REDIS_PASS=$(python3 -c "import secrets; print(secrets.token_hex(16))" 2>/dev/null || openssl rand -hex 16)

    cat > .env << EOF
# VulnScanner v8 — Configuração de produção
SECRET_KEY=${SECRET_KEY}
DB_PASSWORD=${DB_PASS}
REDIS_PASSWORD=${REDIS_PASS}

# Portas
HTTP_PORT=80
HTTPS_PORT=443

# Claude API (Attack Chain Engine com IA — opcional)
ANTHROPIC_API_KEY=

# SMTP para notificações (opcional)
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=

# Playwright (crawler SPA)
PLAYWRIGHT_ENABLED=true

FLASK_ENV=production
EOF
    echo -e "${GREEN}✓ .env criado${NC}"
fi

# Cria SSL self-signed se não existir
mkdir -p deploy/ssl
if [ ! -f deploy/ssl/cert.pem ]; then
    echo ""
    echo -e "${YELLOW}Gerando certificado SSL self-signed...${NC}"
    openssl req -x509 -newkey rsa:4096 -keyout deploy/ssl/key.pem \
        -out deploy/ssl/cert.pem -days 365 -nodes \
        -subj "/C=BR/ST=SP/L=SP/O=VulnScanner/CN=localhost" 2>/dev/null
    echo -e "${GREEN}✓ SSL self-signed gerado (substitua por certificado real em produção)${NC}"
fi

# Build e start
echo ""
echo -e "${YELLOW}Fazendo build e iniciando containers...${NC}"
docker-compose build --no-cache
docker-compose up -d

# Aguarda app subir
echo ""
echo -e "${YELLOW}Aguardando app iniciar...${NC}"
for i in {1..30}; do
    if curl -sf http://localhost/health > /dev/null 2>&1; then
        echo -e "${GREEN}✓ App está rodando!${NC}"
        break
    fi
    sleep 2
    echo -n "."
done

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  VulnScanner v8.0 está no ar! 🔍         ║${NC}"
echo -e "${GREEN}║                                          ║${NC}"
echo -e "${GREEN}║  Dashboard: https://localhost            ║${NC}"
echo -e "${GREEN}║  API Docs:  https://localhost/api/docs   ║${NC}"
echo -e "${GREEN}║                                          ║${NC}"
echo -e "${GREEN}║  Primeiro acesso: criar conta em        ║${NC}"
echo -e "${GREEN}║  https://localhost/auth/register        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Logs: docker-compose logs -f app${NC}"
echo -e "${YELLOW}Stop: docker-compose down${NC}"
