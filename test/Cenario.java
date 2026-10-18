// Gabriel de Barros Arruda - 2311723
// Erica Oliveira Regnier - 2211893

import static org.junit.Assert.*;

import java.io.*;
import java.nio.file.*;
import java.sql.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

class Cenario implements Closeable {

    static final String SENHA_ADMIN  = "13572468";
    static final String SENHA_USER01 = "24681357";
    static final String SENHA_USER02 = "9753186420";

    private static GeradorPacote.Pacote pacote;

    final File dir;
    final AtomicLong agora = new AtomicLong(System.currentTimeMillis());
    final Banco banco;
    final Sistema sistema;
    final Map<String, String> segredos = new HashMap<String, String>();
    final Map<String, String> senhas = new HashMap<String, String>();

    static synchronized GeradorPacote.Pacote pacote() throws Exception {
        if (pacote == null) {
            File destino = Files.createTempDirectory("pacote-cofre").toFile();
            pacote = GeradorPacote.gerar(destino);
            apagarAoSair(destino);
        }
        return pacote;
    }

    Cenario() throws Exception {
        pacote();
        dir = Files.createTempDirectory("cenario-cofre").toFile();
        apagarAoSair(dir);
        banco = new Banco(new File(dir, "cofre.db").getPath());
        sistema = new Sistema(banco, agora::get);
    }

    GeradorPacote.Pacote p() {
        return pacote;
    }

    Cadastro.Formulario formulario(GeradorPacote.Identidade id, String senha, int gid) {
        Cadastro.Formulario f = new Cadastro.Formulario();
        f.caminhoCertificado = id.arquivoCertificado.getPath();
        f.caminhoChavePrivada = id.arquivoChave.getPath();
        f.fraseSecreta = id.frase.toCharArray();
        f.gid = gid;
        f.senha = senha.toCharArray();
        f.confirmacaoSenha = senha.toCharArray();
        return f;
    }

    Cadastro.Confirmacao cadastrar(GeradorPacote.Identidade id, String senha, int gid, Usuario operador)
            throws Exception {
        Cadastro.Preparacao prep = sistema.getCadastro().preparar(formulario(id, senha, gid), operador);
        assertTrue("cadastro de " + id.email + ": " + prep.mensagem, prep.ok());
        Cadastro.Confirmacao c = sistema.getCadastro().confirmar(prep, operador);
        assertEquals(Cadastro.StatusConfirmacao.CADASTRADO, c.status);
        segredos.put(id.email, c.segredoTotpBase32);
        senhas.put(id.email, senha);
        return c;
    }

    void cadastrarTodos() throws Exception {
        assertEquals(Sistema.Partida.CADASTRO_ADMINISTRADOR, sistema.iniciar());
        Usuario admin = cadastrar(pacote.admin, SENHA_ADMIN, Usuario.GID_ADMINISTRADOR, null).usuario;
        sistema.definirFraseAdministrador(pacote.admin.frase.toCharArray());
        cadastrar(pacote.user01, SENHA_USER01, Usuario.GID_USUARIO, admin);
        cadastrar(pacote.user02, SENHA_USER02, Usuario.GID_USUARIO, admin);
    }

    static List<char[]> digitar(String senha) {
        TecladoVirtual teclado = new TecladoVirtual();
        for (char digito : senha.toCharArray()) {
            for (int b = 0; b < TecladoVirtual.BOTOES; b++) {
                char[] botao = teclado.getBotao(b);
                if (botao[0] == digito || botao[1] == digito) {
                    teclado.pressionar(b);
                    break;
                }
            }
        }
        return new ArrayList<char[]>(teclado.getPressionados());
    }

    String token(String email) throws Exception {
        return new TOTP(segredos.get(email), 30).generateCode();
    }

    Usuario entrar(String email) throws Exception {
        Autenticacao a = sistema.getAutenticacao();
        sistema.iniciarAutenticacao();
        assertEquals(Autenticacao.Resultado.LIBERADO, a.identificar(email));
        assertEquals(Autenticacao.Resultado.SENHA_OK, a.verificarSenha(digitar(senhas.get(email))));
        assertEquals(Autenticacao.Resultado.TOKEN_OK, a.verificarToken(token(email)));
        sistema.iniciarSessao();
        return sistema.getUsuarioSessao();
    }

    int marca() throws SQLException {
        try (Statement st = banco.getConexao().createStatement();
             ResultSet rs = st.executeQuery("SELECT COALESCE(MAX(rid), 0) FROM Registros")) {
            return rs.getInt(1);
        }
    }

    List<Integer> mids(int marca) throws SQLException {
        List<Integer> mids = new ArrayList<Integer>();
        try (PreparedStatement ps = banco.getConexao().prepareStatement(
                "SELECT mid FROM Registros WHERE rid > ? ORDER BY rid")) {
            ps.setInt(1, marca);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    mids.add(rs.getInt(1));
                }
            }
        }
        return mids;
    }

    Object[] ultimoRegistro() throws SQLException {
        try (Statement st = banco.getConexao().createStatement();
             ResultSet rs = st.executeQuery(
                 "SELECT mid, uid, login_name, arquivo FROM Registros ORDER BY rid DESC LIMIT 1")) {
            rs.next();
            Object uid = rs.getObject(2);
            return new Object[] {rs.getInt(1), uid == null ? null : ((Number) uid).intValue(),
                                 rs.getString(3), rs.getString(4)};
        }
    }

    static List<Integer> lista(Integer... mids) {
        return Arrays.asList(mids);
    }

    File copiaPastaSegura() throws IOException {
        File destino = new File(dir, "Files-" + System.nanoTime());
        assertTrue(destino.mkdirs());
        for (File f : pacote.files.listFiles()) {
            Files.copy(f.toPath(), new File(destino, f.getName()).toPath());
        }
        return destino;
    }

    @Override
    public void close() throws IOException {
        try {
            banco.close();
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }

    static void apagarAoSair(final File dir) {
        Runtime.getRuntime().addShutdownHook(new Thread() {
            public void run() {
                apagar(dir);
            }
        });
    }

    static void apagar(File f) {
        File[] filhos = f.listFiles();
        if (filhos != null) {
            for (File c : filhos) {
                apagar(c);
            }
        }
        f.delete();
    }
}
