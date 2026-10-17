import static org.junit.Assert.*;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.sql.*;
import java.util.*;
import org.junit.*;

//
// Cadastro de usuarios: criticas do formulario (6003 a 6007), confirmacao (6008 e
// 6009) e armazenamento (Usuarios / Chaveiro, bcrypt, chave TOTP cifrada)
public class CadastroTest {

    private Cenario c;
    private GeradorPacote.Pacote p;
    private Usuario admin;

    @Before
    public void antes() throws Exception {
        c = new Cenario();
        p = c.p();
        c.sistema.iniciar();
        admin = c.cadastrar(p.admin, Cenario.SENHA_ADMIN, Usuario.GID_ADMINISTRADOR, null).usuario;
    }

    @After
    public void depois() throws Exception {
        c.close();
    }

    // =====================================================================
    // Criticas do formulario
    // =====================================================================

    @Test
    public void senhaPessoalInvalidaRegistra6003() throws Exception {
        String[][] casos = {{"1357246", "1357246"}, {"13572468091", "13572468091"}, {"1357246a", "1357246a"},
                            {"11357246", "11357246"}, {"", ""}, {"24681357", "24681359"}};
        for (String[] caso : casos) {
            Cadastro.Formulario f = c.formulario(p.user01, caso[0], Usuario.GID_USUARIO);
            f.confirmacaoSenha = caso[1].toCharArray();
            assertFalha(f, Cadastro.Status.SENHA_INVALIDA, Mensagens.CADASTRO_SENHA_INVALIDA);
        }
    }

    @Test
    public void senhaDiferenteDaConfirmacaoTemMensagemPropria() throws Exception {
        Cadastro.Formulario f = c.formulario(p.user01, "24681357", Usuario.GID_USUARIO);
        f.confirmacaoSenha = "24681359".toCharArray();
        Cadastro.Preparacao prep = c.sistema.getCadastro().preparar(f, admin);
        assertTrue(prep.mensagem, prep.mensagem.contains("diferentes"));
    }

    @Test
    public void certificadoInvalidoRegistra6004() throws Exception {
        File lixo = new File(c.dir, "lixo.crt");
        Files.write(lixo.toPath(), "nao eh um certificado".getBytes(StandardCharsets.US_ASCII));
        for (String caminho : new String[] {"/nao/existe.crt", "", p.keys.getPath(), lixo.getPath(),
                                            p.user01.arquivoChave.getPath()}) {
            Cadastro.Formulario f = c.formulario(p.user01, Cenario.SENHA_USER01, Usuario.GID_USUARIO);
            f.caminhoCertificado = caminho;
            assertFalha(f, Cadastro.Status.CERTIFICADO_INVALIDO, Mensagens.CADASTRO_CERTIFICADO_INVALIDO);
        }
    }

    @Test
    public void caminhoMaiorQue255CaracteresEhInvalido() throws Exception {
        Cadastro.Formulario f = c.formulario(p.user01, Cenario.SENHA_USER01, Usuario.GID_USUARIO);
        f.caminhoCertificado = p.user01.arquivoCertificado.getPath() + new String(new char[256]).replace('\0', ' ');
        assertFalha(f, Cadastro.Status.CERTIFICADO_INVALIDO, Mensagens.CADASTRO_CERTIFICADO_INVALIDO);
    }

    @Test
    public void caminhoDaChavePrivadaInvalidoRegistra6005() throws Exception {
        for (String caminho : new String[] {"/nao/existe.key", "", p.keys.getPath()}) {
            Cadastro.Formulario f = c.formulario(p.user01, Cenario.SENHA_USER01, Usuario.GID_USUARIO);
            f.caminhoChavePrivada = caminho;
            assertFalha(f, Cadastro.Status.CHAVE_CAMINHO_INVALIDO, Mensagens.CHAVE_CAMINHO_INVALIDO);
        }
    }

    @Test
    public void fraseSecretaInvalidaRegistra6006() throws Exception {
        for (String frase : new String[] {"user02", "", "USER01", "user01 "}) {
            Cadastro.Formulario f = c.formulario(p.user01, Cenario.SENHA_USER01, Usuario.GID_USUARIO);
            f.fraseSecreta = frase.toCharArray();
            assertFalha(f, Cadastro.Status.CHAVE_FRASE_INVALIDA, Mensagens.CHAVE_FRASE_INVALIDA);
        }
    }

    @Test
    public void chavePrivadaDeOutroCertificadoRegistra6007() throws Exception {
        Cadastro.Formulario f = c.formulario(p.user01, Cenario.SENHA_USER01, Usuario.GID_USUARIO);
        f.caminhoChavePrivada = p.user02.arquivoChave.getPath();
        f.fraseSecreta = p.user02.frase.toCharArray();
        assertFalha(f, Cadastro.Status.CHAVE_ASSINATURA_INVALIDA, Mensagens.CHAVE_ASSINATURA_INVALIDA);
    }

    // =====================================================================
    // Confirmacao e armazenamento
    // =====================================================================

    @Test
    public void telaDeConfirmacaoApresentaOsCamposDoCertificado() throws Exception {
        Cadastro.Preparacao prep = preparar(p.user01, Cenario.SENHA_USER01);
        Map<String, String> d = prep.dadosCertificado();
        assertEquals(Arrays.asList("Versão", "Série", "Validade", "Tipo de Assinatura", "Emissor",
                                   "Sujeito (Friendly Name)", "E-mail"), new ArrayList<String>(d.keySet()));
        assertEquals("V3", d.get("Versão"));
        assertEquals("3", d.get("Série"));
        assertEquals("SHA256withRSA", d.get("Tipo de Assinatura"));
        assertTrue(d.get("Emissor"), d.get("Emissor").contains("CN=AC INF1416"));
        assertTrue(d.get("Emissor"), d.get("Emissor").contains("EMAILADDRESS=ca@inf1416.puc-rio.br"));
        assertEquals("Usuario 01", d.get("Sujeito (Friendly Name)"));
        assertEquals("user01@inf1416.puc-rio.br", d.get("E-mail"));
        assertTrue(d.get("Validade").contains(" a "));
    }

    @Test
    public void cadastroConfirmadoRegistra6002e6008EIncluiOUsuario() throws Exception {
        int m = c.marca();
        Cadastro.Confirmacao conf = c.cadastrar(p.user01, Cenario.SENHA_USER01, Usuario.GID_USUARIO, admin);
        assertEquals(Cenario.lista(Mensagens.BOTAO_CADASTRAR, Mensagens.CONFIRMACAO_ACEITA), c.mids(m));
        assertEquals(2, c.banco.totalUsuarios());

        Usuario u = c.banco.buscarUsuario("user01@inf1416.puc-rio.br");
        assertEquals("Usuario 01", u.getNome());
        assertEquals(Usuario.GID_USUARIO, u.getGid());
        assertEquals("Usuário", u.getGrupo());
        assertEquals(u.getUid(), conf.usuario.getUid());
        assertNotNull(u.getKid());
    }

    @Test
    public void chaveiroGuardaChavePrivadaCifradaECertificadoPemAssociadosAoUid() throws Exception {
        Usuario u = c.cadastrar(p.user01, Cenario.SENHA_USER01, Usuario.GID_USUARIO, admin).usuario;
        try (PreparedStatement ps = c.banco.getConexao().prepareStatement(
                "SELECT kid, uid, certificado_pem, chave_privada FROM Chaveiro WHERE kid = ?")) {
            ps.setInt(1, u.getKid());
            ResultSet rs = ps.executeQuery();
            assertTrue(rs.next());
            assertEquals(u.getUid(), rs.getInt("uid"));
            String pem = rs.getString("certificado_pem");
            assertTrue(pem.startsWith("-----BEGIN CERTIFICATE-----"));
            assertEquals(p.user01.certificado, CriptoUtil.certificadoDePem(pem));
            // chave privada no formato criptografado (binario), igual ao arquivo
            assertArrayEquals(Files.readAllBytes(p.user01.arquivoChave.toPath()), rs.getBytes("chave_privada"));
        }
        assertNotEquals(admin.getKid(), u.getKid());
    }

    @Test
    public void senhaPessoalArmazenadaComBcrypt2yCusto8() throws Exception {
        c.cadastrar(p.user01, Cenario.SENHA_USER01, Usuario.GID_USUARIO, admin);
        String senha = valor("SELECT senha FROM Usuarios WHERE login_name = 'user01@inf1416.puc-rio.br'");
        assertEquals(60, senha.length());
        assertTrue(senha.startsWith("$2y$08$"));
        assertTrue(Senha.verificar(senha, Cenario.SENHA_USER01.toCharArray()));
        assertFalse(senha.contains(Cenario.SENHA_USER01));
    }

    @Test
    public void chaveTotpDe20BytesEmBase32CifradaComAChaveDaSenhaPessoal() throws Exception {
        Cadastro.Confirmacao conf = c.cadastrar(p.user01, Cenario.SENHA_USER01, Usuario.GID_USUARIO, admin);
        assertEquals(32, conf.segredoTotpBase32.length());
        assertEquals(20, new Base32(Base32.Alphabet.BASE32, false, false).fromString(conf.segredoTotpBase32).length);

        Usuario u = c.banco.buscarUsuario("user01@inf1416.puc-rio.br");
        String armazenado = new String(u.chaveTotp, StandardCharsets.ISO_8859_1);
        assertFalse("a chave TOTP nao pode ficar em claro", armazenado.contains(conf.segredoTotpBase32));
        byte[] decifrado = CriptoUtil.decifrarAES(CriptoUtil.chaveAES(Cenario.SENHA_USER01.toCharArray()), u.chaveTotp);
        assertEquals(conf.segredoTotpBase32, new String(decifrado, StandardCharsets.US_ASCII));
    }

    @Test
    public void uriOtpAuthParaOGoogleAuthenticator() throws Exception {
        Cadastro.Confirmacao conf = c.cadastrar(p.user01, Cenario.SENHA_USER01, Usuario.GID_USUARIO, admin);
        assertEquals("otpauth://totp/Cofre%20Digital:user01@inf1416.puc-rio.br?secret=" + conf.segredoTotpBase32,
                     conf.uriOtpAuth);
    }

    @Test
    public void segredosTotpSaoDiferentesParaCadaUsuario() throws Exception {
        String s1 = c.cadastrar(p.user01, Cenario.SENHA_USER01, Usuario.GID_USUARIO, admin).segredoTotpBase32;
        String s2 = c.cadastrar(p.user02, Cenario.SENHA_USER02, Usuario.GID_USUARIO, admin).segredoTotpBase32;
        assertNotEquals(s1, s2);
        assertNotEquals(c.segredos.get(p.admin.email), s1);
    }

    @Test
    public void loginNameDuplicadoNaoEhIncluido() throws Exception {
        Cadastro.Preparacao prep = preparar(p.admin, "97531864");
        assertTrue(prep.ok());
        int m = c.marca();
        Cadastro.Confirmacao conf = c.sistema.getCadastro().confirmar(prep, admin);
        assertEquals(Cadastro.StatusConfirmacao.LOGIN_DUPLICADO, conf.status);
        assertEquals(Cenario.lista(Mensagens.CONFIRMACAO_ACEITA), c.mids(m));
        assertEquals(1, c.banco.totalUsuarios());
    }

    @Test
    public void confirmacaoRejeitadaRegistra6009ENaoInclui() throws Exception {
        Cadastro.Preparacao prep = preparar(p.user01, Cenario.SENHA_USER01);
        int m = c.marca();
        c.sistema.getCadastro().rejeitar(prep, admin);
        assertEquals(Cenario.lista(Mensagens.CONFIRMACAO_REJEITADA), c.mids(m));
        assertEquals(1, c.banco.totalUsuarios());
    }

    @Test
    public void grupoAdministradorPodeSerEscolhido() throws Exception {
        Usuario u = c.cadastrar(p.user02, Cenario.SENHA_USER02, Usuario.GID_ADMINISTRADOR, admin).usuario;
        assertTrue(u.isAdministrador());
        assertEquals("Administrador", u.getGrupo());
    }

    @Test
    public void primeiroUsuarioEhSempreAdministrador() throws Exception {
        try (Cenario novo = new Cenario()) {
            Usuario u = novo.cadastrar(p.user01, Cenario.SENHA_USER01, Usuario.GID_USUARIO, null).usuario;
            assertTrue(u.isAdministrador());
        }
    }

    @Test
    public void registrosDoCadastroIdentificamOOperador() throws Exception {
        Cadastro.Formulario f = c.formulario(p.user01, "1", Usuario.GID_USUARIO);
        c.sistema.getCadastro().preparar(f, admin);
        Object[] r = c.ultimoRegistro();
        assertEquals(Mensagens.CADASTRO_SENHA_INVALIDA, r[0]);
        assertEquals(admin.getUid(), r[1]);
    }

    // =====================================================================
    // Auxiliares
    // =====================================================================

    private Cadastro.Preparacao preparar(GeradorPacote.Identidade id, String senha) throws Exception {
        return c.sistema.getCadastro().preparar(c.formulario(id, senha, Usuario.GID_USUARIO), admin);
    }

    private void assertFalha(Cadastro.Formulario f, Cadastro.Status status, int mid) throws Exception {
        int m = c.marca();
        Cadastro.Preparacao prep = c.sistema.getCadastro().preparar(f, admin);
        assertEquals(status, prep.status);
        assertFalse(prep.ok());
        assertNotNull(prep.mensagem);
        assertEquals(Cenario.lista(Mensagens.BOTAO_CADASTRAR, mid), c.mids(m));
        assertEquals("o usuario nao pode ser cadastrado", 1, c.banco.totalUsuarios());
    }

    private String valor(String sql) throws SQLException {
        try (Statement st = c.banco.getConexao().createStatement(); ResultSet rs = st.executeQuery(sql)) {
            return rs.getString(1);
        }
    }
}
