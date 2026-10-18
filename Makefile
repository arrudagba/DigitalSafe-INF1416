# Gabriel de Barros Arruda - 2311723
# Erica Oliveira Regnier - 2211893

JAVAC   := javac --release 8 -encoding UTF-8 -Xlint:-options
LIB_APP := lib/bcprov-jdk18on-1.79.jar:lib/sqlite-jdbc-3.50.3.0.jar:lib/zxing-core-3.5.4.jar
CP_JAR  := ../lib/bcprov-jdk18on-1.79.jar ../lib/sqlite-jdbc-3.50.3.0.jar

SRC    := $(wildcard src/*.java)
FERR   := $(wildcard ferramentas/*.java)
TESTES := $(wildcard test/*.java)

# make run DB=outro.db | make logview CHAVE=... | make token SEGREDO=... | make pacote PASTA=...
DB      ?=
CHAVE   ?= pacote/Keys/admin-pkcs8-aes.key
SEGREDO ?=
PASTA   ?= pacote

.PHONY: all run run-linux test logview token pacote clean clean-db

all: dist/CofreDigital.jar dist/LogView.jar build/ferramentas.ok build/testes.ok

build/classes.ok: $(SRC)
	@echo "Compilando src/ ..."
	@rm -rf build/classes && mkdir -p build/classes
	@$(JAVAC) -cp "$(LIB_APP)" -d build/classes $(SRC)
	@touch $@

build/ferramentas.ok: build/classes.ok $(FERR)
	@echo "Compilando ferramentas/ ..."
	@rm -rf build/ferramentas && mkdir -p build/ferramentas
	@$(JAVAC) -cp "build/classes:lib/*" -d build/ferramentas $(FERR)
	@touch $@

build/testes.ok: build/classes.ok build/ferramentas.ok $(TESTES)
	@echo "Compilando test/ ..."
	@rm -rf build/testes && mkdir -p build/testes
	@$(JAVAC) -cp "build/classes:build/ferramentas:lib/*" -d build/testes $(TESTES)
	@touch $@

dist/CofreDigital.jar: build/classes.ok
	@echo "Gerando $@ ..."
	@mkdir -p dist
	@printf 'Main-Class: CofreDigital\nClass-Path: $(CP_JAR) ../lib/zxing-core-3.5.4.jar\n' > build/cofre.mf
	@cd build/classes && jar cfm ../../$@ ../cofre.mf $$(ls *.class | grep -v '^LogView')

# programa de auditoria separado: apenas as classes que ele usa
dist/LogView.jar: build/classes.ok
	@echo "Gerando $@ ..."
	@mkdir -p dist
	@printf 'Main-Class: LogView\nClass-Path: $(CP_JAR)\n' > build/logview.mf
	@cd build/classes && jar cfm ../../$@ ../logview.mf LogView*.class Banco*.class Usuario*.class CriptoUtil*.class Mensagens*.class

run: dist/CofreDigital.jar
	java -jar dist/CofreDigital.jar $(DB)

# telas HiDPI no Linux
run-linux: dist/CofreDigital.jar
	GDK_SCALE=2 GDK_DPI_SCALE=1 java -jar dist/CofreDigital.jar $(DB)

test: build/testes.ok
	java -cp "build/classes:build/ferramentas:build/testes:lib/*" org.junit.runner.JUnitCore \
		$(basename $(notdir $(wildcard test/*Test.java)))

logview: dist/LogView.jar
	java -jar dist/LogView.jar $(CHAVE) $(DB)

token: build/ferramentas.ok
	@test -n "$(SEGREDO)" || { echo "Uso: make token SEGREDO=<CHAVE_BASE32>"; exit 1; }
	@java -cp "build/classes:build/ferramentas" GerarToken $(SEGREDO)

pacote: build/ferramentas.ok
	rm -rf $(PASTA)
	java -cp "build/classes:build/ferramentas:lib/*" GeradorPacote $(PASTA)

clean:
	rm -rf build dist

clean-db:
	rm -f cofre.db cofre.db-*
