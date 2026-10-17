import java.io.File;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.*;

//
// Cadastro de usuarios (Tela de Cadastro e cadastro do administrador na partida)
public class Cadastro {

    public static final int TAMANHO_CAMPO = 255;

    //
    // dados do Formulario de Cadastro
    public static class Formulario {
        public String caminhoCertificado;
        public String caminhoChavePrivada;
        public char[] fraseSecreta;
        public int gid = Usuario.GID_USUARIO;
        public char[] senha;
        public char[] confirmacaoSenha;

        public void apagar() {
            if (fraseSecreta != null) Arrays.fill(fraseSecreta, '\0');
            if (senha != null) Arrays.fill(senha, '\0');
            if (confirmacaoSenha != null) Arrays.fill(confirmacaoSenha, '\0');
        }
    }

    public enum Status {
        PRONTO_PARA_CONFIRMAR,
        SENHA_INVALIDA,
        CERTIFICADO_INVALIDO,
        CHAVE_CAMINHO_INVALIDO,
        CHAVE_FRASE_INVALIDA,
        CHAVE_ASSINATURA_INVALIDA
    }

    //
    // resultado do Botao Cadastrar: erro ou dados do certificado para a tela de confirmacao
    public static class Preparacao {
        public final Status status;
        public final String mensagem;
        X509Certificate certificado;
        byte[] chavePrivadaCifrada;
        String senhaBcrypt;
        char[] senha;
        int gid;

        Preparacao(Status status, String mensagem) {
            this.status = status;
            this.mensagem = mensagem;
        }

        public boolean ok() {
            return status == Status.PRONTO_PARA_CONFIRMAR;
        }

        //
        // campos do certificado apresentados na tela de confirmacao
        public Map<String, String> dadosCertificado() {
            SimpleDateFormat f = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
            Map<String, String> d = new LinkedHashMap<String, String>();
            d.put("Versão", "V" + certificado.getVersion());
            d.put("Série", CriptoUtil.serialHex(certificado.getSerialNumber()));
            d.put("Validade", f.format(certificado.getNotBefore()) + " a " + f.format(certificado.getNotAfter()));
            d.put("Tipo de Assinatura", certificado.getSigAlgName());
            d.put("Emissor", CriptoUtil.nomeLegivel(certificado.getIssuerX500Principal()));
            d.put("Sujeito (Friendly Name)", CriptoUtil.extrairNome(certificado));
            d.put("E-mail", CriptoUtil.extrairEmail(certificado));
            return d;
        }

        public void apagar() {
            if (senha != null) Arrays.fill(senha, '\0');
        }
    }

    public enum StatusConfirmacao { CADASTRADO, LOGIN_DUPLICADO }

    public static class Confirmacao {
        public final StatusConfirmacao status;
        public final Usuario usuario;
        public final String segredoTotpBase32;
        public final String uriOtpAuth;

        Confirmacao(StatusConfirmacao status, Usuario usuario, String segredo, String uri) {
            this.status = status;
            this.usuario = usuario;
            this.segredoTotpBase32 = segredo;
            this.uriOtpAuth = uri;
        }
    }

    private final Banco banco;
    private final Log log;

    public Cadastro(Banco banco, Log log) {
        this.banco = banco;
        this.log = log;
    }

    //
    // Botao Cadastrar: critica os campos, testa a frase secreta e verifica a chave
    // privada com a assinatura de um array aleatorio de 10240 bytes
    public Preparacao preparar(Formulario f, Usuario operador) throws SQLException {
        log.registrar(Mensagens.BOTAO_CADASTRAR, operador);

        if (f.senha == null || f.confirmacaoSenha == null || !Senha.formatoValido(f.senha)
                || !Arrays.equals(f.senha, f.confirmacaoSenha)) {
            log.registrar(Mensagens.CADASTRO_SENHA_INVALIDA, operador);
            String motivo = (f.senha != null && f.confirmacaoSenha != null && Senha.formatoValido(f.senha))
                          ? "A senha pessoal e a confirmação são diferentes."
                          : "A senha pessoal deve ter 8, 9 ou 10 dígitos (0 a 9), sem números repetidos em sequência.";
            return new Preparacao(Status.SENHA_INVALIDA, motivo);
        }

        X509Certificate certificado = lerCertificado(f.caminhoCertificado);
        if (certificado == null) {
            log.registrar(Mensagens.CADASTRO_CERTIFICADO_INVALIDO, operador);
            return new Preparacao(Status.CERTIFICADO_INVALIDO,
                "Caminho do certificado digital inválido (arquivo inexistente, ilegível ou sem e-mail no Sujeito).");
        }

        byte[] chaveCifrada = campoValido(f.caminhoChavePrivada) ? CriptoUtil.lerArquivo(f.caminhoChavePrivada) : null;
        if (chaveCifrada == null) {
            log.registrar(Mensagens.CHAVE_CAMINHO_INVALIDO, operador);
            return new Preparacao(Status.CHAVE_CAMINHO_INVALIDO, "Caminho do arquivo da chave privada inválido.");
        }
        if (f.fraseSecreta == null || f.fraseSecreta.length == 0 || f.fraseSecreta.length > TAMANHO_CAMPO) {
            log.registrar(Mensagens.CHAVE_FRASE_INVALIDA, operador);
            return new Preparacao(Status.CHAVE_FRASE_INVALIDA, "Frase secreta inválida.");
        }
        CriptoUtil.ResultadoChave chave = CriptoUtil.validarChavePrivada(chaveCifrada, f.fraseSecreta,
                                                                         certificado, CriptoUtil.TESTE_CADASTRO);
        switch (chave.status) {
            case FRASE_INVALIDA:
                log.registrar(Mensagens.CHAVE_FRASE_INVALIDA, operador);
                return new Preparacao(Status.CHAVE_FRASE_INVALIDA,
                    "Frase secreta inválida: não foi possível decriptar a chave privada.");
            case ASSINATURA_INVALIDA:
                log.registrar(Mensagens.CHAVE_ASSINATURA_INVALIDA, operador);
                return new Preparacao(Status.CHAVE_ASSINATURA_INVALIDA,
                    "A chave privada não corresponde à chave pública do certificado digital (assinatura inválida).");
            case CAMINHO_INVALIDO:
                log.registrar(Mensagens.CHAVE_CAMINHO_INVALIDO, operador);
                return new Preparacao(Status.CHAVE_CAMINHO_INVALIDO, "Caminho do arquivo da chave privada inválido.");
            default:
                break;
        }

        Preparacao p = new Preparacao(Status.PRONTO_PARA_CONFIRMAR, null);
        p.certificado = certificado;
        p.chavePrivadaCifrada = chaveCifrada;
        p.senhaBcrypt = Senha.gerarHash(f.senha);
        p.senha = f.senha.clone();
        // o primeiro usuario do sistema eh sempre o administrador
        p.gid = banco.totalUsuarios() == 0 ? Usuario.GID_ADMINISTRADOR : f.gid;
        return p;
    }

    //
    // dados confirmados: inclui o usuario somente se o login name for unico
    public Confirmacao confirmar(Preparacao p, Usuario operador) throws Exception {
        if (!p.ok()) {
            throw new IllegalArgumentException("Cadastro nao preparado: " + p.status);
        }
        log.registrar(Mensagens.CONFIRMACAO_ACEITA, operador);
        try {
            String loginName = CriptoUtil.extrairEmail(p.certificado);
            if (banco.buscarUsuario(loginName) != null) {
                return new Confirmacao(StatusConfirmacao.LOGIN_DUPLICADO, null, null, null);
            }
            // chave secreta TOTP: 20 bytes aleatorios, codificados em BASE32 e
            // cifrados com AES/ECB/PKCS5Padding e chave gerada a partir da senha pessoal
            byte[] segredo = new byte[20];
            new SecureRandom().nextBytes(segredo);
            String base32 = new Base32(Base32.Alphabet.BASE32, false, false).toString(segredo);
            Arrays.fill(segredo, (byte) 0);
            byte[] totpCifrado = CriptoUtil.cifrarAES(CriptoUtil.chaveAES(p.senha),
                                                      base32.getBytes(StandardCharsets.US_ASCII));

            int uid = banco.inserirUsuario(CriptoUtil.extrairNome(p.certificado), loginName, p.gid, p.senhaBcrypt,
                                           totpCifrado, CriptoUtil.paraPem(p.certificado), p.chavePrivadaCifrada);
            Usuario usuario = banco.buscarUsuario(uid);
            return new Confirmacao(StatusConfirmacao.CADASTRADO, usuario, base32, uriOtpAuth(loginName, base32));
        } finally {
            p.apagar();
        }
    }

    public void rejeitar(Preparacao p, Usuario operador) {
        log.registrar(Mensagens.CONFIRMACAO_REJEITADA, operador);
        p.apagar();
    }

    //
    // otpauth://totp/Cofre%20Digital:<login>?secret=<BASE32>
    public static String uriOtpAuth(String loginName, String base32) {
        try {
            String conta = URLEncoder.encode(loginName, "UTF-8").replace("%40", "@");
            return "otpauth://totp/Cofre%20Digital:" + conta + "?secret=" + base32;
        } catch (java.io.UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static boolean campoValido(String campo) {
        return campo != null && !campo.trim().isEmpty() && campo.length() <= TAMANHO_CAMPO;
    }

    private static X509Certificate lerCertificado(String caminho) {
        if (!campoValido(caminho)) {
            return null;
        }
        File arquivo = new File(caminho.trim());
        if (!arquivo.isFile()) {
            return null;
        }
        try {
            X509Certificate certificado = CriptoUtil.carregarCertificado(arquivo);
            String email = CriptoUtil.extrairEmail(certificado);
            String nome = CriptoUtil.extrairNome(certificado);
            if (!CriptoUtil.emailValido(email) || nome == null || nome.isEmpty()) {
                return null;
            }
            return certificado;
        } catch (Exception e) {
            return null;
        }
    }
}
