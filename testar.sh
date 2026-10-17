#!/usr/bin/env bash
# Executa todos os testes automatizados (JUnit 4)
set -e
cd "$(dirname "$0")"
[ -d build/testes ] || ./compilar.sh
TESTES=$(cd test && ls *Test.java | sed 's/\.java$//')
java -cp "build/classes:build/ferramentas:build/testes:lib/*" org.junit.runner.JUnitCore $TESTES
