#!/usr/bin/env bash
# Gera (ou regenera) o pacote de teste: certificados, chaves privadas e pasta segura
set -e
cd "$(dirname "$0")"
[ -d build/ferramentas ] || ./compilar.sh
rm -rf "${1:-pacote}"
java -cp "build/classes:build/ferramentas:lib/*" GeradorPacote "${1:-pacote}"
