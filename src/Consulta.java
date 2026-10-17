import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.text.Normalizer;
import java.util.*;

//
// Consulta da pasta de arquivos secretos do usuario
public class Consulta {

    //
    // arquivo da pasta segura que o usuario pode visualizar
    public static class Entrada {
        public enum Acesso { DONO, COMPARTILHADO, GRUPO }

        public final String nomeCodigo;
        public final String nomeSecreto;
        public final String dono;
        public final String grupo;
        public final Acesso acesso;
        public final String idCompartilhamento;

        Entrada(String nomeCodigo, String nomeSecreto, String dono, String grupo, Acesso acesso, String id) {
            this.nomeCodigo = nomeCodigo;
            this.nomeSecreto = nomeSecreto;
            this.dono = dono;
            this.grupo = grupo;
            this.acesso = acesso;
            this.idCompartilhamento = id;
        }
    }

    public enum StatusListagem {
        OK,
        FRASE_INVALIDA,
        ASSINATURA_INVALIDA,
        CAMINHO_INVALIDO,
        INDICE_FALHA_DECRIPTACAO,
        INDICE_FALHA_VERIFICACAO
    }

    public static class Listagem {
        public final StatusListagem status;
        public final String mensagem;
        public final List<Entrada> entradas;
        public final String avisoShare;
        final File pasta;
        final PrivateKey chaveUsuario;

        Listagem(StatusListagem status, String mensagem, List<Entrada> entradas, String avisoShare,
                 File pasta, PrivateKey chaveUsuario) {
            this.status = status;
            this.mensagem = mensagem;
            this.entradas = entradas;
            this.avisoShare = avisoShare;
            this.pasta = pasta;
            this.chaveUsuario = chaveUsuario;
        }

        static Listagem erro(StatusListagem status, String mensagem) {
            return new Listagem(status, mensagem, Collections.<Entrada>emptyList(), null, null, null);
        }

        public boolean ok() {
            return status == StatusListagem.OK;
        }
    }

    public enum StatusArquivo { OK, ACESSO_NEGADO, FALHA_DECRIPTACAO, FALHA_VERIFICACAO, FALHA_GRAVACAO }

    public static class ResultadoArquivo {
        public final StatusArquivo status;
        public final String mensagem;
        public final File arquivoGravado;

        ResultadoArquivo(StatusArquivo status, String mensagem, File arquivoGravado) {
            this.status = status;
            this.mensagem = mensagem;
            this.arquivoGravado = arquivoGravado;
        }
    }

    private final Banco banco;
    private final Log log;

    public Consulta(Banco banco, Log log) {
        this.banco = banco;
        this.log = log;
    }

    //
    // Botao Listar: valida a frase secreta do usuario, decripta e verifica os
    // arquivos index e share (protegidos com as chaves do administrador) e lista
    // os arquivos que o usuario pode acessar
    public Listagem listar(Usuario usuario, String caminhoPasta, char[] fraseUsuario, char[] fraseAdministrador)
            throws SQLException {
        log.registrar(Mensagens.BOTAO_LISTAR, usuario);
        banco.incrementarConsultas(usuario.uid);
        usuario.totalConsultas++;

        // frase secreta validada da mesma forma que no cadastro do usuario
        CriptoUtil.ResultadoChave chaveUsuario = validarChave(usuario, fraseUsuario);
        if (chaveUsuario.status == CriptoUtil.StatusChave.FRASE_INVALIDA
                || chaveUsuario.status == CriptoUtil.StatusChave.CAMINHO_INVALIDO) {
            log.registrar(Mensagens.CHAVE_FRASE_INVALIDA, usuario);
            return Listagem.erro(StatusListagem.FRASE_INVALIDA, "Frase secreta inválida.");
        }
        if (chaveUsuario.status == CriptoUtil.StatusChave.ASSINATURA_INVALIDA) {
            log.registrar(Mensagens.CHAVE_ASSINATURA_INVALIDA, usuario);
            return Listagem.erro(StatusListagem.ASSINATURA_INVALIDA,
                                 "A chave privada não corresponde ao certificado digital (assinatura inválida).");
        }

        File pasta = caminhoPasta == null || caminhoPasta.trim().isEmpty() ? null : new File(caminhoPasta.trim());
        if (pasta == null || !pasta.isDirectory()) {
            log.registrar(Mensagens.CONSULTA_CAMINHO_INVALIDO, usuario);
            return Listagem.erro(StatusListagem.CAMINHO_INVALIDO, "Caminho de pasta inválido.");
        }

        Usuario admin = banco.administradorDoSistema();
        PrivateKey chaveAdmin = validarChave(admin, fraseAdministrador).chave;
        PublicKey publicaAdmin = chavePublica(admin);

        // arquivo de indice
        byte[] indice;
        try {
            indice = CriptoUtil.decifrarComEnvelope(ler(pasta, "index.enc"), ler(pasta, "index.env"), chaveAdmin);
            log.registrar(Mensagens.INDICE_DECRIPTADO, usuario);
        } catch (Exception e) {
            log.registrar(Mensagens.INDICE_FALHA_DECRIPTACAO, usuario);
            return Listagem.erro(StatusListagem.INDICE_FALHA_DECRIPTACAO,
                                 "Falha na decriptação do arquivo de índice (index.enc / index.env).");
        }
        if (!assinaturaValida(indice, pasta, "index.asd", publicaAdmin)) {
            log.registrar(Mensagens.INDICE_FALHA_VERIFICACAO, usuario);
            return Listagem.erro(StatusListagem.INDICE_FALHA_VERIFICACAO,
                                 "Falha na verificação (integridade e autenticidade) do arquivo de índice.");
        }
        log.registrar(Mensagens.INDICE_VERIFICADO, usuario);

        // arquivo de compartilhamento: em caso de falha, lista apenas os arquivos do indice
        String avisoShare = null;
        byte[] share = null;
        try {
            share = CriptoUtil.decifrarComEnvelope(ler(pasta, "share.enc"), ler(pasta, "share.env"), chaveAdmin);
            log.registrar(Mensagens.SHARE_DECRIPTADO, usuario);
        } catch (Exception e) {
            log.registrar(Mensagens.SHARE_FALHA_DECRIPTACAO, usuario);
            avisoShare = "Falha na decriptação do arquivo de share: os compartilhamentos não serão listados.";
        }
        if (share != null) {
            if (assinaturaValida(share, pasta, "share.asd", publicaAdmin)) {
                log.registrar(Mensagens.SHARE_VERIFICADO, usuario);
            } else {
                log.registrar(Mensagens.SHARE_FALHA_VERIFICACAO, usuario);
                avisoShare = "Falha na verificação (integridade e autenticidade) do arquivo de share: "
                           + "os compartilhamentos não serão listados.";
                share = null;
            }
        }

        List<Entrada> entradas = filtrar(usuario, linhas(indice), share != null ? linhas(share) : null);
        log.registrar(Mensagens.INDICE_LISTA_APRESENTADA, usuario);
        if (share != null) {
            log.registrar(Mensagens.SHARE_LISTA_APRESENTADA, usuario);
        }
        return new Listagem(StatusListagem.OK, null, entradas, avisoShare, pasta, chaveUsuario.chave);
    }

    //
    // politica de controle de acesso: arquivos que o usuario eh dono, arquivos do
    // seu grupo e arquivos compartilhados com ele pelos respectivos donos
    static List<Entrada> filtrar(Usuario usuario, List<String[]> indice, List<String[]> share) {
        List<Entrada> entradas = new ArrayList<Entrada>();
        for (String[] linha : indice) {
            if (linha.length < 4) {
                continue;
            }
            String codigo = linha[0], nome = linha[1], dono = linha[2], grupo = linha[3];
            String id = share == null ? null : idCompartilhamento(share, codigo, usuario.loginName);
            if (dono.equalsIgnoreCase(usuario.loginName)) {
                entradas.add(new Entrada(codigo, nome, dono, grupo, Entrada.Acesso.DONO, null));
            } else if (id != null) {
                entradas.add(new Entrada(codigo, nome, dono, grupo, Entrada.Acesso.COMPARTILHADO, id));
            } else if (mesmoGrupo(grupo, usuario.grupo)) {
                entradas.add(new Entrada(codigo, nome, dono, grupo, Entrada.Acesso.GRUPO, null));
            }
        }
        return entradas;
    }

    private static String idCompartilhamento(List<String[]> share, String codigo, String loginName) {
        for (String[] linha : share) {
            if (linha.length >= 3 && linha[0].equals(codigo) && linha[2].equalsIgnoreCase(loginName)) {
                return linha[1];
            }
        }
        return null;
    }

    //
    // compara o grupo do arquivo com o grupo do usuario, sem diferenciar
    // maiusculas/minusculas e acentos (ex.: "usuario" e "Usuário")
    static boolean mesmoGrupo(String grupoArquivo, String grupoUsuario) {
        return normalizar(grupoArquivo).equals(normalizar(grupoUsuario));
    }

    private static String normalizar(String s) {
        return Normalizer.normalize(s == null ? "" : s, Normalizer.Form.NFD)
                         .replaceAll("\\p{M}", "").toLowerCase(Locale.ROOT);
    }

    //
    // nome secreto selecionado: decripta o arquivo e grava os dados decriptados em
    // um novo arquivo com o nome secreto
    public ResultadoArquivo decriptar(Usuario usuario, Listagem listagem, Entrada entrada) throws SQLException {
        log.registrar(Mensagens.ARQUIVO_SELECIONADO, usuario, entrada.nomeSecreto);
        if (entrada.acesso == Entrada.Acesso.GRUPO || !nomeSeguro(entrada.nomeSecreto)) {
            log.registrar(Mensagens.ARQUIVO_ACESSO_NEGADO, usuario, entrada.nomeSecreto);
            return new ResultadoArquivo(StatusArquivo.ACESSO_NEGADO,
                "Você não tem permissão de acesso ao arquivo " + entrada.nomeSecreto + ".", null);
        }
        log.registrar(Mensagens.ARQUIVO_ACESSO_PERMITIDO, usuario, entrada.nomeSecreto);

        File pasta = listagem.pasta;
        byte[] conteudo;
        try {
            byte[] envelope = entrada.acesso == Entrada.Acesso.DONO
                            ? ler(pasta, entrada.nomeCodigo + ".env")
                            : lerEnvelopeCompartilhado(pasta, entrada.nomeCodigo, entrada.idCompartilhamento);
            conteudo = CriptoUtil.decifrarComEnvelope(ler(pasta, entrada.nomeCodigo + ".enc"), envelope,
                                                      listagem.chaveUsuario);
            log.registrar(Mensagens.ARQUIVO_DECRIPTADO, usuario, entrada.nomeSecreto);
        } catch (Exception e) {
            log.registrar(Mensagens.ARQUIVO_FALHA_DECRIPTACAO, usuario, entrada.nomeSecreto);
            return new ResultadoArquivo(StatusArquivo.FALHA_DECRIPTACAO,
                "Falha na decriptação do arquivo " + entrada.nomeSecreto + " (sigilo).", null);
        }

        // a assinatura digital do arquivo eh gerada com a chave privada do dono
        Usuario dono = banco.buscarUsuario(entrada.dono);
        PublicKey publicaDono = dono == null ? null : chavePublica(dono);
        if (publicaDono == null
                || !assinaturaValida(conteudo, pasta, entrada.nomeCodigo + ".asd", publicaDono)) {
            log.registrar(Mensagens.ARQUIVO_FALHA_VERIFICACAO, usuario, entrada.nomeSecreto);
            return new ResultadoArquivo(StatusArquivo.FALHA_VERIFICACAO,
                "Falha na verificação (integridade e autenticidade) do arquivo " + entrada.nomeSecreto + ".", null);
        }
        log.registrar(Mensagens.ARQUIVO_VERIFICADO, usuario, entrada.nomeSecreto);

        File destino = new File(pasta, entrada.nomeSecreto);
        try {
            Files.write(destino.toPath(), conteudo);
        } catch (IOException e) {
            return new ResultadoArquivo(StatusArquivo.FALHA_GRAVACAO,
                "Não foi possível gravar o arquivo " + destino.getPath() + ": " + e.getMessage(), null);
        } finally {
            Arrays.fill(conteudo, (byte) 0);
        }
        return new ResultadoArquivo(StatusArquivo.OK,
            "Arquivo " + entrada.nomeSecreto + " decriptado e gravado em " + destino.getPath() + ".", destino);
    }

    //
    // envelope do arquivo compartilhado: nome codigo + identificador do
    // compartilhamento + extensao .shr (aceita os separadores mais comuns)
    private static byte[] lerEnvelopeCompartilhado(File pasta, String codigo, String id) throws IOException {
        for (String separador : new String[] {"", "_", "-", "."}) {
            File arquivo = new File(pasta, codigo + separador + id + ".shr");
            if (arquivo.isFile()) {
                return Files.readAllBytes(arquivo.toPath());
            }
        }
        throw new FileNotFoundException("Envelope .shr do compartilhamento " + id + " de " + codigo);
    }

    //
    // o nome secreto vem do indice: nao pode conter caminho (evita gravar fora da pasta)
    private static boolean nomeSeguro(String nome) {
        return !nome.isEmpty() && new File(nome).getName().equals(nome) && !nome.equals("..") && !nome.equals(".");
    }

    private CriptoUtil.ResultadoChave validarChave(Usuario usuario, char[] frase) throws SQLException {
        if (usuario == null || usuario.kid == null || frase == null) {
            return new CriptoUtil.ResultadoChave(CriptoUtil.StatusChave.FRASE_INVALIDA, null);
        }
        try {
            X509Certificate certificado = CriptoUtil.certificadoDePem(banco.certificadoPem(usuario.kid));
            return CriptoUtil.validarChavePrivada(banco.chavePrivadaCifrada(usuario.kid), frase, certificado,
                                                  CriptoUtil.TESTE_CADASTRO);
        } catch (java.security.cert.CertificateException e) {
            return new CriptoUtil.ResultadoChave(CriptoUtil.StatusChave.ASSINATURA_INVALIDA, null);
        }
    }

    private PublicKey chavePublica(Usuario usuario) throws SQLException {
        if (usuario == null || usuario.kid == null) {
            return null;
        }
        try {
            return CriptoUtil.certificadoDePem(banco.certificadoPem(usuario.kid)).getPublicKey();
        } catch (java.security.cert.CertificateException e) {
            return null;
        }
    }

    private static boolean assinaturaValida(byte[] dados, File pasta, String arquivoAssinatura, PublicKey publica) {
        if (publica == null) {
            return false;
        }
        try {
            return CriptoUtil.verificarAssinatura(dados, ler(pasta, arquivoAssinatura), publica);
        } catch (IOException e) {
            return false;
        }
    }

    private static byte[] ler(File pasta, String nome) throws IOException {
        return Files.readAllBytes(new File(pasta, nome).toPath());
    }

    //
    // linhas do arquivo decriptado, separadas em campos por espaco
    static List<String[]> linhas(byte[] conteudo) {
        List<String[]> linhas = new ArrayList<String[]>();
        for (String linha : new String(conteudo, StandardCharsets.UTF_8).split("\r?\n")) {
            String t = linha.trim();
            if (!t.isEmpty()) {
                linhas.add(t.split("\\s+"));
            }
        }
        return linhas;
    }
}
