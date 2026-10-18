// Gabriel de Barros Arruda - 2311723
// Erica Oliveira Regnier - 2211893

import static org.junit.Assert.*;

import java.io.*;
import java.util.*;
import org.junit.*;

public class LogViewTest {

    private Cenario c;
    private GeradorPacote.Pacote p;

    @Before
    public void antes() throws Exception {
        c = new Cenario();
        p = c.p();
        c.cadastrarTodos();
    }

    @After
    public void depois() throws Exception {
        c.close();
    }

    @Test
    public void administradorEhAutenticadoComChavePrivadaEFraseSecreta() throws Exception {
        Usuario u = LogView.autenticar(c.banco, p.admin.arquivoChave.getPath(), "admin".toCharArray());
        assertNotNull(u);
        assertEquals(GeradorPacote.ADMIN, u.getLoginName());
    }

    @Test
    public void fraseSecretaErradaNaoAutentica() throws Exception {
        assertNull(LogView.autenticar(c.banco, p.admin.arquivoChave.getPath(), "user01".toCharArray()));
        assertNull(LogView.autenticar(c.banco, p.admin.arquivoChave.getPath(), "".toCharArray()));
    }

    @Test
    public void usuarioQueNaoEhAdministradorNaoAutentica() throws Exception {
        assertNull(LogView.autenticar(c.banco, p.user01.arquivoChave.getPath(), "user01".toCharArray()));
    }

    @Test
    public void caminhoDaChavePrivadaInvalidoNaoAutentica() throws Exception {
        assertNull(LogView.autenticar(c.banco, "/nao/existe.key", "admin".toCharArray()));
        assertNull(LogView.autenticar(c.banco, p.keys.getPath(), "admin".toCharArray()));
        assertNull(LogView.autenticar(c.banco, p.admin.arquivoCertificado.getPath(), "admin".toCharArray()));
    }

    @Test
    public void outroAdministradorCadastradoTambemPodeExecutar() throws Exception {
        try (Cenario outro = new Cenario()) {
            outro.sistema.iniciar();
            Usuario admin = outro.cadastrar(p.admin, Cenario.SENHA_ADMIN, Usuario.GID_ADMINISTRADOR, null).usuario;
            outro.cadastrar(p.user02, Cenario.SENHA_USER02, Usuario.GID_ADMINISTRADOR, admin);
            Usuario u = LogView.autenticar(outro.banco, p.user02.arquivoChave.getPath(), "user02".toCharArray());
            assertNotNull(u);
            assertEquals(GeradorPacote.USER02, u.getLoginName());
        }
    }

    @Test
    public void registrosSaoApresentadosEmOrdemCronologica() throws Exception {
        long base = c.agora.get();
        Log log = c.sistema.getLog();
        c.agora.set(base + 30000);
        log.registrar(Mensagens.SISTEMA_ENCERRADO);
        c.agora.set(base + 10000);
        log.registrar(Mensagens.ETAPA1_INICIADA);
        c.agora.set(base + 20000);
        log.registrar(Mensagens.LOGIN_NAO_IDENTIFICADO, "intruso@exemplo.com");

        List<Banco.Registro> registros = c.banco.registrosCronologicos();
        for (int i = 1; i < registros.size(); i++) {
            assertTrue(registros.get(i - 1).dataHora <= registros.get(i).dataHora);
        }
        int n = registros.size();
        assertEquals(Mensagens.ETAPA1_INICIADA, registros.get(n - 3).mid);
        assertEquals(Mensagens.LOGIN_NAO_IDENTIFICADO, registros.get(n - 2).mid);
        assertEquals(Mensagens.SISTEMA_ENCERRADO, registros.get(n - 1).mid);
    }

    @Test
    public void saidaTemDataHoraCodigoEMensagem() throws Exception {
        c.entrar(GeradorPacote.USER01);
        c.sistema.getLog().registrar(Mensagens.ARQUIVO_SELECIONADO, c.sistema.getUsuarioSessao(), "doc.txt");
        c.sistema.getLog().registrar(Mensagens.LOGIN_NAO_IDENTIFICADO, "intruso@exemplo.com");

        ByteArrayOutputStream saida = new ByteArrayOutputStream();
        LogView.imprimir(c.banco, new PrintStream(saida, true, "UTF-8"));
        String texto = saida.toString("UTF-8");
        String data = "[0-9]{2}/[0-9]{2}/[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}";

        assertTrue(texto, texto.matches("(?s).*" + data + "  1001    Sistema iniciado\\..*"));
        assertTrue(texto, texto.contains("1005    Partida do sistema iniciada para cadastro do administrador."));
        assertTrue(texto, texto.contains("1003    Sessão iniciada para user01@inf1416.puc-rio.br."));
        assertTrue(texto, texto.contains(
            "7015    Arquivo doc.txt selecionado por user01@inf1416.puc-rio.br para decriptação."));
        assertTrue(texto, texto.contains("2005    Login name intruso@exemplo.com não identificado."));
        // registros sem usuario (partida)
        assertTrue(texto, texto.contains("6002    Botão cadastrar pressionado por -."));
        assertTrue(texto.indexOf("1001    ") < texto.indexOf("1003    "));
        assertTrue(texto.indexOf("1003    ") < texto.indexOf("7015    "));
    }

    @Test
    public void logViewEhUmProgramaSeparadoDoCofreDigital() throws Exception {
        // o Cofre Digital nao referencia o LogView
        for (String fonte : new String[] {"CofreDigital.java", "Sistema.java", "Autenticacao.java", "Consulta.java"}) {
            File f = new File("src", fonte);
            if (f.isFile()) {
                String codigo = new String(java.nio.file.Files.readAllBytes(f.toPath()), "UTF-8");
                assertFalse(fonte, codigo.contains("LogView"));
            }
        }
        LogView.class.getMethod("main", String[].class);
    }
}
