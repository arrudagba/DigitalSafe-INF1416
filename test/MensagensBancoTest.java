import static org.junit.Assert.*;

import java.sql.*;
import java.util.*;
import org.junit.*;

//
// Tabela de Mensagens de Registro e estrutura do banco de dados
public class MensagensBancoTest {

    private Cenario c;

    @Before
    public void antes() throws Exception {
        c = new Cenario();
    }

    @After
    public void depois() throws Exception {
        c.close();
    }

    @Test
    public void tabelaTemTodosOsCodigosDoAnexo() {
        Set<Integer> esperados = new TreeSet<Integer>();
        int[][] faixas = {{1001, 1006}, {2001, 2005}, {3001, 3007}, {4001, 4007},
                          {5001, 5004}, {6001, 6010}, {7001, 7021}, {8001, 8004}};
        for (int[] f : faixas) {
            for (int mid = f[0]; mid <= f[1]; mid++) {
                esperados.add(mid);
            }
        }
        assertEquals(64, esperados.size());
        assertEquals(esperados, new TreeSet<Integer>(Mensagens.TABELA.keySet()));
    }

    @Test
    public void textosDasMensagensConferemComOAnexo() {
        assertEquals("Sistema iniciado.", Mensagens.TABELA.get(1001));
        assertEquals("Partida do sistema iniciada para operação normal pelos usuários.", Mensagens.TABELA.get(1006));
        assertEquals("Login name <login_name> não identificado.", Mensagens.TABELA.get(2005));
        assertEquals("Acesso do usuario <login_name> bloqueado pela autenticação etapa 2.", Mensagens.TABELA.get(3007));
        assertEquals("Acesso do usuario <login_name> bloqueado pela autenticação etapa 3.", Mensagens.TABELA.get(4007));
        assertEquals("Chave privada verificada negativamente para <login_name> (assinatura digital inválida).",
                     Mensagens.TABELA.get(6007));
        assertEquals("Arquivo <arq_name> selecionado por <login_name> para decriptação.", Mensagens.TABELA.get(7015));
        assertEquals("Botão voltar de sair para o menu principal pressionado por <login_name>.",
                     Mensagens.TABELA.get(8004));
    }

    @Test
    public void formatarSubstituiLoginEArquivo() {
        assertEquals("Arquivo doc.txt selecionado por a@b.com para decriptação.",
                     Mensagens.formatar(Mensagens.TABELA.get(7015), "a@b.com", "doc.txt"));
        assertEquals("Sistema iniciado.", Mensagens.formatar(Mensagens.TABELA.get(1001), null, null));
    }

    @Test
    public void bancoTemAsCincoTabelas() throws Exception {
        Set<String> tabelas = new HashSet<String>();
        try (Statement st = c.banco.getConexao().createStatement();
             ResultSet rs = st.executeQuery("SELECT name FROM sqlite_master WHERE type = 'table'")) {
            while (rs.next()) {
                tabelas.add(rs.getString(1));
            }
        }
        assertTrue(tabelas.containsAll(Arrays.asList("Usuarios", "Chaveiro", "Grupos", "Mensagens", "Registros")));
    }

    @Test
    public void mensagensFicamNaTabelaMensagens() throws Exception {
        Map<Integer, String> noBanco = new LinkedHashMap<Integer, String>();
        try (Statement st = c.banco.getConexao().createStatement();
             ResultSet rs = st.executeQuery("SELECT mid, texto FROM Mensagens ORDER BY mid")) {
            while (rs.next()) {
                noBanco.put(rs.getInt(1), rs.getString(2));
            }
        }
        assertEquals(Mensagens.TABELA, noBanco);
    }

    @Test
    public void registrosNaoArmazenamOTextoDasMensagens() throws Exception {
        assertEquals(Arrays.asList("rid", "data_hora", "mid", "uid", "login_name", "arquivo"), colunas("Registros"));
        c.sistema.iniciar();
        try (Statement st = c.banco.getConexao().createStatement();
             ResultSet rs = st.executeQuery("SELECT * FROM Registros")) {
            while (rs.next()) {
                for (int i = 1; i <= rs.getMetaData().getColumnCount(); i++) {
                    Object v = rs.getObject(i);
                    assertFalse(v != null && Mensagens.TABELA.containsValue(v.toString()));
                }
            }
        }
    }

    @Test
    public void tabelaUsuariosEChaveiro() throws Exception {
        assertTrue(colunas("Usuarios").containsAll(Arrays.asList("uid", "nome", "login_name", "gid", "kid", "senha",
                                                                 "chave_totp", "total_acessos", "bloqueado_ate")));
        assertEquals(Arrays.asList("kid", "uid", "certificado_pem", "chave_privada"), colunas("Chaveiro"));
    }

    @Test
    public void gruposComGidDecimalUnico() throws Exception {
        assertEquals("Administrador", c.banco.nomeGrupo(1));
        assertEquals("Usuário", c.banco.nomeGrupo(2));
        assertNull(c.banco.nomeGrupo(3));
    }

    @Test
    public void reabrirOBancoNaoDuplicaGruposNemMensagens() throws Exception {
        String caminho = new java.io.File(c.dir, "cofre.db").getPath();
        new Banco(caminho).close();
        try (Statement st = c.banco.getConexao().createStatement()) {
            ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM Grupos");
            assertEquals(2, rs.getInt(1));
            rs = st.executeQuery("SELECT COUNT(*) FROM Mensagens");
            assertEquals(64, rs.getInt(1));
        }
    }

    private List<String> colunas(String tabela) throws SQLException {
        List<String> colunas = new ArrayList<String>();
        try (Statement st = c.banco.getConexao().createStatement();
             ResultSet rs = st.executeQuery("PRAGMA table_info(" + tabela + ")")) {
            while (rs.next()) {
                colunas.add(rs.getString("name"));
            }
        }
        return colunas;
    }
}
