#!/usr/bin/env bash
# Mostra o codigo TOTP atual de uma chave BASE32 (substitui o Google Authenticator nos testes)
cd "$(dirname "$0")"
[ -d build/ferramentas ] || ./compilar.sh
exec java -cp "build/classes:build/ferramentas" GerarToken "$@"
