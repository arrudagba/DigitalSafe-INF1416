#!/usr/bin/env bash
# Compila o Cofre Digital, o LogView, as ferramentas e os testes, e gera os JARs em dist/
set -e
cd "$(dirname "$0")"

LIB_APP="lib/bcprov-jdk18on-1.79.jar:lib/sqlite-jdbc-3.50.3.0.jar:lib/zxing-core-3.5.4.jar"
JAVAC="javac --release 8 -encoding UTF-8 -Xlint:-options"

rm -rf build dist
mkdir -p build/classes build/ferramentas build/testes dist

echo "Compilando src/ ..."
$JAVAC -cp "$LIB_APP" -d build/classes src/*.java
echo "Compilando ferramentas/ ..."
$JAVAC -cp "build/classes:lib/*" -d build/ferramentas ferramentas/*.java
echo "Compilando test/ ..."
$JAVAC -cp "build/classes:build/ferramentas:lib/*" -d build/testes test/*.java

echo "Gerando dist/CofreDigital.jar e dist/LogView.jar ..."
CLASSPATH_JAR="../lib/bcprov-jdk18on-1.79.jar ../lib/sqlite-jdbc-3.50.3.0.jar"
printf 'Main-Class: CofreDigital\nClass-Path: %s ../lib/zxing-core-3.5.4.jar\n' "$CLASSPATH_JAR" > build/cofre.mf
printf 'Main-Class: LogView\nClass-Path: %s\n' "$CLASSPATH_JAR" > build/logview.mf

# programa de auditoria separado: apenas as classes de banco/criptografia necessarias
LOGVIEW=$(cd build/classes && ls LogView*.class Banco*.class Usuario*.class CriptoUtil*.class Mensagens*.class)
COFRE=$(cd build/classes && ls *.class | grep -v '^LogView')
(cd build/classes && jar cfm ../../dist/LogView.jar ../logview.mf $LOGVIEW)
(cd build/classes && jar cfm ../../dist/CofreDigital.jar ../cofre.mf $COFRE)
echo "OK"
