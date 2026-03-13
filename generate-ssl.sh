#!/bin/bash
# generate-ssl.sh — Generate self-signed TLS certificate for development
# For production, replace with Let's Encrypt or your CA certificate

set -e

mkdir -p nginx/ssl

openssl req -x509 -nodes -days 365 \
    -newkey rsa:2048 \
    -keyout nginx/ssl/server.key \
    -out nginx/ssl/server.crt \
    -subj "/C=US/ST=Dev/L=Local/O=APIScanner/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    2>/dev/null

chmod 600 nginx/ssl/server.key
chmod 644 nginx/ssl/server.crt

echo "✅ SSL certificate generated:"
echo "   nginx/ssl/server.crt  (certificate)"
echo "   nginx/ssl/server.key  (private key — keep secret)"
echo ""
echo "⚠️  This is a self-signed cert for development only."
echo "   Browsers will show a warning — use 'thisisunsafe' in Chrome or:"
echo "   curl -k https://localhost/health"
