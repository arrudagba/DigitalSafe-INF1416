#!/usr/bin/env bash
# Executa o Cofre Digital (argumento opcional: caminho do banco de dados; padrao cofre.db)
cd "$(dirname "$0")"
[ -f dist/CofreDigital.jar ] || ./compilar.sh
exec java -jar dist/CofreDigital.jar "$@"
