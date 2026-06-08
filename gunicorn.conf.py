# Gunicorn config — VulnScanner v8 produção
bind             = "0.0.0.0:5000"
workers          = 1          # Eventlet usa 1 worker com muitas greenlets
worker_class     = "eventlet" # Necessário para WebSocket / Socket.IO
worker_connections = 1000
timeout          = 300
keepalive        = 5
max_requests     = 500
max_requests_jitter = 50
preload_app      = False
accesslog        = "logs/access.log"
errorlog         = "logs/error.log"
loglevel         = "info"
