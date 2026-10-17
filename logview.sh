#!/usr/bin/env bash
# Executa o LogView: logview.sh <caminho_chave_privada_admin> [caminho_banco]
cd "$(dirname "$0")"
[ -f dist/LogView.jar ] || ./compilar.sh
exec java -jar dist/LogView.jar "$@"
