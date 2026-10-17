# Trabalho 3 – Cofre Digital (Digital Vault)

INF1416 – Segurança da Informação – PUC-Rio

Sistema em Java (JDK SE, interface Swing) com banco de dados SQLite, autenticação
multifator em três etapas (login name, senha pessoal no teclado virtual sobrecarregado e
token TOTP do Google Authenticator) e controle de integridade, autenticidade e sigilo de uma
pasta de arquivos secretos. Inclui o programa de auditoria **LogView**, separado do cofre.

## Requisitos

- JDK 8 ou superior (`javac` e `java` no PATH). O código é compilado com `--release 8`.
- As bibliotecas já estão em `lib/`:
  - `bcprov-jdk18on-1.79.jar`: BouncyCastle (`OpenBSDBCrypt`, bcrypt 2y)
  - `sqlite-jdbc-3.50.3.0.jar`: driver JDBC do SQLite
  - `zxing-core-3.5.4.jar`: desenho do QRCode da URI `otpauth` (não é usado no cálculo do TOTP)
  - `bcpkix`/`bcutil`: usados só pelo gerador do pacote de teste
  - `junit-4.13.2.jar` e `hamcrest-core-1.3.jar`: testes

## Estrutura

```
src/            código do Cofre Digital e do LogView
  CofreDigital.java   interface gráfica (telas)
  Sistema.java        partida, sessão, navegação e registros das telas
  Autenticacao.java   etapas 1, 2 e 3, contagem de erros e bloqueio de 2 minutos
  Cadastro.java       cadastro de usuários (críticas, confirmação, Chaveiro)
  Consulta.java       pasta segura: index/share, controle de acesso e decriptação
  TOTP.java           TOTP (estrutura do anexo; só Mac, SecretKeySpec, Date e Base32)
  Base32.java         classe fornecida no anexo
  QRCodeOtp.java      QRCode da URI otpauth para o Google Authenticator
  Senha.java          regras da senha, bcrypt 2y/custo 8, verificação pelos pares do teclado
  TecladoVirtual.java 5 botões com 2 números, redistribuídos a cada pressionamento
  CriptoUtil.java     AES/ECB/PKCS5Padding + SHA1PRNG, PKCS8, X.509, envelope e assinatura
  Banco.java          tabelas Usuarios, Chaveiro, Grupos, Mensagens e Registros
  Mensagens.java      Tabela de Mensagens de Registro (anexo)
  Log.java            gravação dos registros
  LogView.java        programa de auditoria (separado)
test/           testes automatizados (JUnit 4)
ferramentas/    GeradorPacote (material de teste) e GerarToken (código TOTP)
pacote/         material de teste já gerado (certificados, chaves e pasta segura)
lib/            bibliotecas
```

## Compilação

Linux/macOS:

```bash
./compilar.sh
```

O script compila `src/`, `ferramentas/` e `test/` e gera dois JARs:

- `dist/CofreDigital.jar`: o Cofre Digital
- `dist/LogView.jar`: o programa de auditoria, que **não contém** as classes do cofre

Compilação manual (Windows: troque `:` por `;` no classpath):

```bash
mkdir -p build/classes
javac --release 8 -encoding UTF-8 -cp "lib/*" -d build/classes src/*.java
java -cp "build/classes:lib/*" CofreDigital
java -cp "build/classes:lib/*" LogView pacote/Keys/admin-pkcs8-aes.key
```

## Testes automatizados

```bash
./testar.sh
```

São 143 testes, que levam cerca de 30 s e não precisam de interface gráfica. Cada teste cria
um banco temporário e usa um pacote de teste gerado na hora. Um relógio controlável permite
testar o bloqueio de 2 minutos sem esperar.

| Classe de teste | O que cobre |
|---|---|
| `MensagensBancoTest` | as 64 mensagens do anexo (texto exato), as 5 tabelas, a tabela Mensagens no banco e Registros sem o texto das mensagens |
| `TOTPBase32Test` | vetores do RFC 4648 e do RFC 6238, 6 algarismos com zeros à esquerda, margem de ±30 s, rejeição fora da margem e chave BASE32 inválida |
| `SenhaTecladoTest` | 8, 9 ou 10 dígitos, sem repetições em sequência; bcrypt `$2y$08$` com 60 caracteres; exemplo do enunciado; descoberta da senha pelos pares do teclado; teclado com 5×2 números sem repetição, redistribuído a cada pressionamento |
| `CriptoUtilTest` | chave AES 256 via SHA1PRNG, chave privada com frase certa ou errada, validação da chave (OK / frase / assinatura / caminho), extração de nome e e-mail do Sujeito, PEM, envelope digital e assinatura digital |
| `CadastroTest` | 6002 a 6009: senha inválida, certificado inválido, caminho da chave, frase, assinatura (chave de outro certificado), confirmação aceita ou rejeitada, login duplicado; KID no Chaveiro, chave privada cifrada (binária), certificado PEM, bcrypt e chave TOTP cifrada |
| `AutenticacaoTest` | 2001 a 2005, 3001 a 3007 e 4001 a 4007: login não identificado, liberado ou bloqueado; 3 erros de senha → bloqueio de 2 minutos; 3 erros de token → bloqueio; erros não consecutivos; outros usuários durante o bloqueio; senha apagada da memória |
| `SistemaTest` | 1001 a 1006: primeira partida (cadastro do administrador) e segunda partida (frase do administrador certa ou errada); 5001 a 5004, 6001, 6010, 7001, 7002 e 8001 a 8004 (navegação); encerrar sessão ou sistema; frase apagada ao encerrar |
| `ConsultaTest` | 7003 a 7021: listagem por dono, grupo ou compartilhamento (admin, user01 e user02); frase inválida; caminho inválido; index adulterado ou com envelope errado; share com falha; decriptação do dono e via `.shr`; acesso negado; falha de decriptação; falha de verificação; nome com caminho |
| `QRCodeOtpTest` | o QRCode gerado é decodificado de volta e contém exatamente a URI `otpauth`; o segredo lido gera um token aceito pelo sistema |
| `LogViewTest` | autenticação do administrador (2048 bytes), frase errada, usuário não administrador, ordem cronológica, formato data/hora/código/mensagem |

## Pacote de teste

A pasta `pacote/` já vem pronta. Para regenerá-la (as chaves mudam a cada geração):

```bash
./gerar_pacote.sh
```

| Usuário | Certificado | Chave privada | Frase secreta |
|---|---|---|---|
| admin@inf1416.puc-rio.br | `pacote/Keys/admin-x509.crt` | `pacote/Keys/admin-pkcs8-aes.key` | `admin` |
| user01@inf1416.puc-rio.br | `pacote/Keys/user01-x509.crt` | `pacote/Keys/user01-pkcs8-aes.key` | `user01` |
| user02@inf1416.puc-rio.br | `pacote/Keys/user02-x509.crt` | `pacote/Keys/user02-pkcs8-aes.key` | `user02` |

Pasta segura: `pacote/Files`

| Nome código | Nome secreto | Dono / grupo | Observação |
|---|---|---|---|
| XXYYZZ00 | docAdmin.txt | admin / administrador | |
| XXYYZZ01 | docUser01.txt | user01 / usuario | compartilhado com user02 (`XXYYZZ01_1.shr`) |
| XXYYZZ02 | docUser02.txt | user02 / usuario | |
| XXYYZZ03 | relatorioAdmin.txt | admin / administrador | compartilhado com user01 (`XXYYZZ03_2.shr`) |
| XXYYZZ04 | assinaturaInvalida.txt | user01 / usuario | `.asd` não confere → registro 7021 |
| XXYYZZ05 | envelopeInvalido.txt | user01 / usuario | `.env` gerado para o user02 → registro 7020 |

Se você recebeu o pacote oficial do professor, basta usá-lo no lugar deste.

> **Importante:** se regenerar o pacote, apague o `cofre.db`, porque os certificados cadastrados
> deixam de corresponder às novas chaves.

## Fluxo de uso normal

Senhas pessoais sugeridas: admin `13572468`, user01 `24681357`, user02 `9753186420`.

### 1. Primeira execução: cadastro do administrador

```bash
rm -f cofre.db cofre.db-*      # começa do zero
./cofre.sh                     # ou: java -jar dist/CofreDigital.jar [caminho_do_banco]
```

Sem usuários cadastrados, o sistema abre o cadastro do administrador (registro 1005):

1. Preencha:
   - Certificado: `pacote/Keys/admin-x509.crt`
   - Chave privada: `pacote/Keys/admin-pkcs8-aes.key`
   - Frase secreta: `admin`
   - Senha pessoal e confirmação: `13572468`
2. Clique em **Cadastrar**. A tela de confirmação mostra Versão, Série, Validade, Tipo de
   Assinatura, Emissor, Sujeito e E-mail. Confirme.
3. O sistema mostra o **QRCode**, a **chave secreta TOTP em BASE32** e a URI `otpauth://...`.
   No Google Authenticator, toque em **+ → Ler QR code** e aponte para a tela. Outra opção é
   "Inserir chave de configuração" com a chave BASE32, tipo "Baseada no horário".
   Sem celular, use `./token.sh <CHAVE_BASE32>` para obter o código atual.

A frase secreta do administrador fica em memória e o sistema segue para a autenticação.

### 2. Autenticação

1. **Etapa 1:** digite `admin@inf1416.puc-rio.br`.
2. **Etapa 2:** digite `13572468` no teclado virtual, clicando no botão que contém cada dígito.
   Os números mudam de botão a cada clique. Depois clique em **Verificar senha**.
3. **Etapa 3:** digite o código de 6 dígitos do Google Authenticator (ou do `./token.sh`).

### 3. Menu principal (administrador)

- **1 – Cadastrar um novo usuário:** cadastre o user01 (`pacote/Keys/user01-*`, frase `user01`,
  grupo Usuário, senha `24681357`) e o user02 (`pacote/Keys/user02-*`, frase `user02`, senha
  `9753186420`). Anote a chave TOTP de cada um.
- **2 – Consultar pasta de arquivos secretos:**
  - Caminho da pasta: `pacote/Files`; frase secreta: `admin`. Clique em **Listar**.
  - Dê duplo clique em um arquivo (ou use **Decriptar arquivo selecionado**). O arquivo
    decriptado é gravado na pasta com o nome secreto, por exemplo `pacote/Files/docAdmin.txt`.
- **3 – Sair do Sistema:** escolha **Encerrar Sessão** (volta à autenticação), **Encerrar
  Sistema** ou **Voltar**.

### 4. Usuário comum

Encerre a sessão e entre como `user01@inf1416.puc-rio.br`. O menu não tem a opção 1. Na consulta,
com a frase `user01`, aparecem estes arquivos:

| Arquivo | Acesso | Resultado ao decriptar |
|---|---|---|
| docUser01.txt | dono | decriptado |
| docUser02.txt | grupo | acesso negado (7017) |
| relatorioAdmin.txt | compartilhado | decriptado via `.shr` |
| assinaturaInvalida.txt | dono | falha de verificação (7021) |
| envelopeInvalido.txt | dono | falha de decriptação (7020) |

### 5. Bloqueio

Três senhas erradas seguidas, ou três tokens errados seguidos, bloqueiam o usuário por 2
minutos e voltam para a etapa 1. Outros usuários continuam podendo entrar.

### 6. Segunda execução em diante

```bash
./cofre.sh
```

O sistema pede a frase secreta do administrador (`admin`). Com a frase errada, ele avisa e
encerra. Com a frase certa, segue para a autenticação.

### 7. LogView (auditoria, somente administrador)

```bash
./logview.sh pacote/Keys/admin-pkcs8-aes.key            # usa ./cofre.db
# ou: java -jar dist/LogView.jar <chave_privada> [caminho_do_banco]
```

A frase secreta é lida sem eco; execute em um terminal, não pela IDE. Os registros aparecem em
ordem cronológica, com data, hora, código e mensagem. Uma chave que não seja de administrador,
ou uma frase errada, encerra o programa.

## Decisões de implementação (interpretações do enunciado)

- **Senha pessoal:** "não podem ser aceitas sequências de números repetidos" foi interpretado
  como proibir o mesmo dígito duas vezes seguidas (`11`, `22`, ...).
- **Verificação da senha:** cada clique fornece um par de números. O sistema testa as 2^n
  combinações (n = 8 a 10) contra o hash bcrypt, em paralelo, e descarta as combinações com
  dígitos repetidos em sequência. A senha encontrada gera a chave AES que decifra a chave TOTP
  na etapa 3 e é apagada da memória logo depois.
- **Erros de senha e de token:** a contagem é guardada no banco e continua valendo se a
  autenticação recomeçar. Ela é zerada por uma verificação positiva ou pelo bloqueio.
- **Controle de acesso:** a listagem mostra os arquivos do dono, os do grupo e os
  compartilhados. Só pode decriptar o dono (envelope `.env`) ou quem recebeu o compartilhamento
  (envelope `.shr`). Um arquivo visível apenas pelo grupo recebe "acesso negado" (7017), porque
  não existe envelope para esse usuário.
- **Envelope `.shr`:** o nome é `CODIGO_ID.shr`. Por compatibilidade, também são aceitos
  `CODIGO-ID.shr`, `CODIGO.ID.shr` e `CODIGOID.shr`.
- **Assinaturas:** a verificação aceita SHA1withRSA, SHA256withRSA, SHA512withRSA e MD5withRSA,
  já que o enunciado não fixa o algoritmo. A validação de chave privada usa SHA256withRSA.
- **Chave privada decriptada:** é aceita em PKCS8 BASE64 com ou sem as linhas
  `-----BEGIN/END PRIVATE KEY-----`, e também em DER binário.
- **Falha no share:** os arquivos do índice continuam sendo listados, sem os compartilhamentos,
  e o usuário recebe um aviso.
- **Frase secreta inválida na consulta:** registra 6006, ou 6007 se a chave não corresponder ao
  certificado, porque a tabela não tem código 70xx para esse caso.
- **Cadastro do administrador na partida:** ainda não há usuário logado, então esses registros
  aparecem com `-` no lugar de `<login_name>`.
- **Login name não identificado (2005):** o login digitado é guardado no registro, mas não o
  texto da mensagem.
- **Total de consultas:** aumenta a cada clique em Listar.
- **Grupo do arquivo:** é comparado sem diferenciar maiúsculas e acentos (`usuario` = `Usuário`).
- **Arquivo decriptado:** é gravado na pasta segura com o nome secreto. Nomes com caminho
  (ex.: `../x`) são recusados.
- **QRCode (opcional no enunciado):** o QRCode da URI `otpauth` é desenhado com a biblioteca
  ZXing. A restrição a classes de terceiros vale só para o TOTP, e esse cálculo é feito
  exclusivamente pela classe `TOTP`.
