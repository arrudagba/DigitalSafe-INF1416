// Gabriel de Barros Arruda - 2311723
// Erica Oliveira Regnier - 2211893

import static org.junit.Assert.*;

import java.io.File;
import org.junit.*;

public class SistemaTest {

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
    public void primeiraPartidaIniciaOCadastroDoAdministrador() throws Exception {
        int m = c.marca();
        assertEquals(Sistema.Partida.CADASTRO_ADMINISTRADOR, c.sistema.iniciar());
        assertEquals(Cenario.lista(Mensagens.SISTEMA_INICIADO, Mensagens.PARTIDA_CADASTRO_ADMIN), c.mids(m));
    }

    @Test
    public void segundaPartidaIniciaAOperacaoNormal() throws Exception {
        c.cadastrarTodos();
        try (Sistema segunda = new Sistema(c.banco, c.agora::get)) {
            int m = c.marca();
            assertEquals(Sistema.Partida.OPERACAO_NORMAL, segunda.iniciar());
            assertEquals(Cenario.lista(Mensagens.SISTEMA_INICIADO, Mensagens.PARTIDA_OPERACAO_NORMAL), c.mids(m));
            assertTrue(segunda.validarFraseAdministrador("admin".toCharArray()));
            assertArrayEquals("admin".toCharArray(), segunda.getFraseAdministrador());
        }
    }

    @Test
    public void fraseDoAdministradorInvalidaNaSegundaPartida() throws Exception {
        c.cadastrarTodos();
        Sistema segunda = new Sistema(c.banco, c.agora::get);
        segunda.iniciar();
        assertFalse(segunda.validarFraseAdministrador("errada".toCharArray()));
        assertFalse(segunda.validarFraseAdministrador("user01".toCharArray()));
        assertFalse(segunda.validarFraseAdministrador("".toCharArray()));
        assertNull(segunda.getFraseAdministrador());
        // o sistema notifica e encerra a execucao
        int m = c.marca();
        segunda.encerrar();
        assertEquals(Cenario.lista(Mensagens.SISTEMA_ENCERRADO), c.mids(m));
    }

    @Test
    public void bancoPersistidoEmArquivoEhReabertoNaSegundaPartida() throws Exception {
        c.cadastrarTodos();
        String caminho = new File(c.dir, "cofre.db").getPath();
        try (Sistema segunda = new Sistema(caminho)) {
            assertEquals(Sistema.Partida.OPERACAO_NORMAL, segunda.iniciar());
            assertEquals(3, segunda.totalUsuarios());
            assertTrue(segunda.validarFraseAdministrador("admin".toCharArray()));
        }
    }

    @Test
    public void encerrarApagaAFraseSecretaDaMemoria() throws Exception {
        c.cadastrarTodos();
        char[] frase = c.sistema.getFraseAdministrador();
        assertArrayEquals("admin".toCharArray(), frase);
        c.sistema.encerrar();
        assertNull(c.sistema.getFraseAdministrador());
        assertArrayEquals(new char[5], frase);
    }

    @Test
    public void encerrarRegistraSistemaEncerradoUmaVez() throws Exception {
        c.sistema.iniciar();
        int m = c.marca();
        c.sistema.encerrar();
        c.sistema.encerrar();
        assertEquals(Cenario.lista(Mensagens.SISTEMA_ENCERRADO), c.mids(m));
    }

    @Test
    public void navegacaoDoMenuPrincipalRegistraCadaTela() throws Exception {
        c.cadastrarTodos();
        c.entrar(GeradorPacote.ADMIN);
        Sistema s = c.sistema;
        int m = c.marca();
        s.telaPrincipal();
        s.opcaoCadastrar();
        s.telaCadastro();
        s.voltarDeCadastrar();
        s.telaPrincipal();
        s.opcaoConsultar();
        s.telaConsulta();
        s.voltarDeConsultar();
        s.telaPrincipal();
        s.opcaoSair();
        s.telaSaida();
        s.voltarDeSair();
        assertEquals(Cenario.lista(
            Mensagens.TELA_PRINCIPAL, Mensagens.MENU_OPCAO1, Mensagens.TELA_CADASTRO, Mensagens.BOTAO_VOLTAR_CADASTRO,
            Mensagens.TELA_PRINCIPAL, Mensagens.MENU_OPCAO2, Mensagens.TELA_CONSULTA, Mensagens.BOTAO_VOLTAR_CONSULTA,
            Mensagens.TELA_PRINCIPAL, Mensagens.MENU_OPCAO3, Mensagens.TELA_SAIDA, Mensagens.BOTAO_VOLTAR_SAIDA),
            c.mids(m));
        Object[] r = c.ultimoRegistro();
        assertEquals(c.banco.buscarUsuario(GeradorPacote.ADMIN).getUid(), r[1]);
    }

    @Test
    public void encerrarSessaoVoltaParaAAutenticacao() throws Exception {
        c.cadastrarTodos();
        c.entrar(GeradorPacote.USER01);
        int m = c.marca();
        c.sistema.encerrarSessao();
        assertEquals(Cenario.lista(Mensagens.BOTAO_ENCERRAR_SESSAO, Mensagens.SESSAO_ENCERRADA,
                                   Mensagens.ETAPA1_INICIADA), c.mids(m));
        assertNull(c.sistema.getUsuarioSessao());
        assertEquals(Autenticacao.Etapa.IDENTIFICACAO, c.sistema.getAutenticacao().getEtapa());
        // a frase secreta do administrador continua em memoria
        assertNotNull(c.sistema.getFraseAdministrador());
    }

    @Test
    public void encerrarSistemaPeloBotao() throws Exception {
        c.cadastrarTodos();
        c.entrar(GeradorPacote.USER02);
        int m = c.marca();
        c.sistema.botaoEncerrarSistema();
        assertEquals(Cenario.lista(Mensagens.BOTAO_ENCERRAR_SISTEMA, Mensagens.SESSAO_ENCERRADA,
                                   Mensagens.SISTEMA_ENCERRADO), c.mids(m));
        assertNull(c.sistema.getFraseAdministrador());
    }

    @Test
    public void dadosDoCabecalhoECorpo1() throws Exception {
        c.cadastrarTodos();
        Usuario admin = c.entrar(GeradorPacote.ADMIN);
        assertEquals(GeradorPacote.ADMIN, admin.getLoginName());
        assertEquals("Administrador", admin.getGrupo());
        assertEquals("Administrador", admin.getNome());
        assertEquals(1, admin.getTotalAcessos());
        assertEquals(3, c.sistema.totalUsuarios());

        c.sistema.encerrarSessao();
        Usuario user01 = c.entrar(GeradorPacote.USER01);
        assertEquals("Usuário", user01.getGrupo());
        assertEquals("Usuario 01", user01.getNome());
        assertFalse(user01.isAdministrador());
    }

    @Test
    public void sessaoIdentificaOUsuarioNosRegistros() throws Exception {
        c.cadastrarTodos();
        Usuario u = c.entrar(GeradorPacote.USER01);
        c.sistema.telaPrincipal();
        Object[] r = c.ultimoRegistro();
        assertEquals(Mensagens.TELA_PRINCIPAL, r[0]);
        assertEquals(u.getUid(), r[1]);
    }
}
