// Gabriel de Barros Arruda - 2311723
// Erica Oliveira Regnier - 2211893

import static org.junit.Assert.*;

import java.lang.reflect.Field;
import java.util.*;
import org.junit.*;

public class AutenticacaoTest {

    private static final String ADMIN  = GeradorPacote.ADMIN;
    private static final String USER01 = GeradorPacote.USER01;
    private static final String USER02 = GeradorPacote.USER02;

    private Cenario c;
    private Autenticacao a;

    @Before
    public void antes() throws Exception {
        c = new Cenario();
        c.cadastrarTodos();
        a = c.sistema.getAutenticacao();
        c.sistema.iniciarAutenticacao();
    }

    @After
    public void depois() throws Exception {
        c.close();
    }

    @Test
    public void inicioDaAutenticacaoRegistra2001() throws Exception {
        int m = c.marca();
        c.sistema.iniciarAutenticacao();
        assertEquals(Cenario.lista(Mensagens.ETAPA1_INICIADA), c.mids(m));
        assertEquals(Autenticacao.Etapa.IDENTIFICACAO, a.getEtapa());
    }

    @Test
    public void loginNameNaoIdentificadoPermaneceNaEtapa1() throws Exception {
        for (String login : new String[] {"desconhecido@inf1416.puc-rio.br", "admin", "", "user01@", "nao e email"}) {
            int m = c.marca();
            assertEquals(login, Autenticacao.Resultado.NAO_IDENTIFICADO, a.identificar(login));
            assertEquals(Cenario.lista(Mensagens.LOGIN_NAO_IDENTIFICADO), c.mids(m));
            assertEquals(Autenticacao.Etapa.IDENTIFICACAO, a.getEtapa());
        }
    }

    @Test
    public void registroGuardaOLoginNameNaoIdentificado() throws Exception {
        a.identificar("intruso@exemplo.com");
        Object[] r = c.ultimoRegistro();
        assertEquals(Mensagens.LOGIN_NAO_IDENTIFICADO, r[0]);
        assertNull(r[1]);
        assertEquals("intruso@exemplo.com", r[2]);
    }

    @Test
    public void loginNameLiberadoSegueParaAEtapa2() throws Exception {
        int m = c.marca();
        assertEquals(Autenticacao.Resultado.LIBERADO, a.identificar(USER01));
        assertEquals(Cenario.lista(Mensagens.LOGIN_LIBERADO, Mensagens.ETAPA1_ENCERRADA, Mensagens.ETAPA2_INICIADA),
                     c.mids(m));
        assertEquals(Autenticacao.Etapa.SENHA, a.getEtapa());
        assertEquals(USER01, a.getUsuario().getLoginName());
    }

    @Test
    public void loginNameNaoDiferenciaMaiusculasEEspacos() throws Exception {
        assertEquals(Autenticacao.Resultado.LIBERADO, a.identificar("  USER01@INF1416.puc-rio.br "));
    }

    @Test
    public void senhaCorretaSegueParaAEtapa3() throws Exception {
        a.identificar(USER01);
        int m = c.marca();
        assertEquals(Autenticacao.Resultado.SENHA_OK, a.verificarSenha(Cenario.digitar(Cenario.SENHA_USER01)));
        assertEquals(Cenario.lista(Mensagens.SENHA_OK, Mensagens.ETAPA2_ENCERRADA, Mensagens.ETAPA3_INICIADA),
                     c.mids(m));
        assertEquals(Autenticacao.Etapa.TOKEN, a.getEtapa());
    }

    @Test
    public void tresErrosDeSenhaBloqueiamOAcessoPor2Minutos() throws Exception {
        a.identificar(USER01);
        int m = c.marca();
        assertEquals(Autenticacao.Resultado.SENHA_INVALIDA, a.verificarSenha(Cenario.digitar("13572468")));
        assertEquals(Autenticacao.Etapa.SENHA, a.getEtapa());
        assertEquals(Autenticacao.Resultado.SENHA_INVALIDA, a.verificarSenha(Cenario.digitar("135724")));
        assertEquals(Autenticacao.Resultado.BLOQUEADO, a.verificarSenha(Cenario.digitar("97531864")));
        assertEquals(Cenario.lista(Mensagens.SENHA_ERRO1, Mensagens.SENHA_ERRO2, Mensagens.SENHA_ERRO3,
                                   Mensagens.SENHA_BLOQUEIO, Mensagens.ETAPA2_ENCERRADA, Mensagens.ETAPA1_INICIADA),
                     c.mids(m));
        // volta para a primeira etapa
        assertEquals(Autenticacao.Etapa.IDENTIFICACAO, a.getEtapa());
        assertBloqueioDe2Minutos(USER01);
    }

    @Test
    public void errosDeSenhaNaoConsecutivosNaoBloqueiam() throws Exception {
        a.identificar(USER01);
        a.verificarSenha(Cenario.digitar("13572468"));
        a.verificarSenha(Cenario.digitar("13572468"));
        assertEquals(Autenticacao.Resultado.SENHA_OK, a.verificarSenha(Cenario.digitar(Cenario.SENHA_USER01)));
        // nova tentativa: a verificacao positiva zerou a contagem
        c.sistema.iniciarAutenticacao();
        a.identificar(USER01);
        int m = c.marca();
        assertEquals(Autenticacao.Resultado.SENHA_INVALIDA, a.verificarSenha(Cenario.digitar("13572468")));
        assertEquals(Cenario.lista(Mensagens.SENHA_ERRO1), c.mids(m));
    }

    @Test
    public void errosDeSenhaContinuamContandoEmUmaNovaTentativa() throws Exception {
        a.identificar(USER01);
        a.verificarSenha(Cenario.digitar("13572468"));
        c.sistema.iniciarAutenticacao();
        a.identificar(USER01);
        int m = c.marca();
        a.verificarSenha(Cenario.digitar("13572468"));
        assertEquals(Cenario.lista(Mensagens.SENHA_ERRO2), c.mids(m));
    }

    @Test
    public void tokenCorretoPermiteAcessoEIniciaASessao() throws Exception {
        a.identificar(USER01);
        a.verificarSenha(Cenario.digitar(Cenario.SENHA_USER01));
        int m = c.marca();
        assertEquals(Autenticacao.Resultado.TOKEN_OK, a.verificarToken(c.token(USER01)));
        assertEquals(Cenario.lista(Mensagens.TOKEN_OK, Mensagens.ETAPA3_ENCERRADA, Mensagens.SESSAO_INICIADA),
                     c.mids(m));
        assertEquals(Autenticacao.Etapa.AUTENTICADO, a.getEtapa());
        assertEquals(1, c.banco.buscarUsuario(USER01).getTotalAcessos());
    }

    @Test
    public void tokenAceitaMargemDe30Segundos() throws Exception {
        a.identificar(USER01);
        a.verificarSenha(Cenario.digitar(Cenario.SENHA_USER01));
        TOTP totp = new TOTP(c.segredos.get(USER01), 30);
        String atrasado = TOTPBase32Test.codigo(totp, TOTPBase32Test.intervaloSeguro() - 1);
        assertEquals(Autenticacao.Resultado.TOKEN_OK, a.verificarToken(atrasado));
    }

    @Test
    public void tokenDeOutroUsuarioEhRecusado() throws Exception {
        a.identificar(USER01);
        a.verificarSenha(Cenario.digitar(Cenario.SENHA_USER01));
        String outro = c.token(USER02);
        Assume.assumeFalse(outro.equals(c.token(USER01)));
        assertEquals(Autenticacao.Resultado.TOKEN_INVALIDO, a.verificarToken(outro));
    }

    @Test
    public void tresErrosDeTokenBloqueiamOAcessoPor2Minutos() throws Exception {
        a.identificar(USER02);
        a.verificarSenha(Cenario.digitar(Cenario.SENHA_USER02));
        int m = c.marca();
        assertEquals(Autenticacao.Resultado.TOKEN_INVALIDO, a.verificarToken(tokenErrado(USER02)));
        // volta para o inicio da terceira etapa
        assertEquals(Autenticacao.Etapa.TOKEN, a.getEtapa());
        assertEquals(Autenticacao.Resultado.TOKEN_INVALIDO, a.verificarToken("abc"));
        assertEquals(Autenticacao.Resultado.BLOQUEADO, a.verificarToken(""));
        assertEquals(Cenario.lista(Mensagens.TOKEN_ERRO1, Mensagens.TOKEN_ERRO2, Mensagens.TOKEN_ERRO3,
                                   Mensagens.TOKEN_BLOQUEIO, Mensagens.ETAPA3_ENCERRADA, Mensagens.ETAPA1_INICIADA),
                     c.mids(m));
        assertEquals(Autenticacao.Etapa.IDENTIFICACAO, a.getEtapa());
        assertBloqueioDe2Minutos(USER02);
    }

    @Test
    public void errosDeTokenNaoConsecutivosNaoBloqueiam() throws Exception {
        a.identificar(USER01);
        a.verificarSenha(Cenario.digitar(Cenario.SENHA_USER01));
        a.verificarToken(tokenErrado(USER01));
        a.verificarToken(tokenErrado(USER01));
        assertEquals(Autenticacao.Resultado.TOKEN_OK, a.verificarToken(c.token(USER01)));
        assertEquals(0, c.banco.buscarUsuario(USER01).errosToken);
    }

    @Test
    public void senhaPessoalEhApagadaDaMemoriaAposAAutenticacao() throws Exception {
        a.identificar(USER01);
        a.verificarSenha(Cenario.digitar(Cenario.SENHA_USER01));
        char[] senha = (char[]) campo(a, "senhaVerificada");
        assertArrayEquals(Cenario.SENHA_USER01.toCharArray(), senha);
        a.verificarToken(c.token(USER01));
        assertNull(campo(a, "senhaVerificada"));
        assertArrayEquals(new char[senha.length], senha);
    }

    @Test
    public void outrosUsuariosPodemEntrarDuranteOBloqueio() throws Exception {
        a.identificar(USER01);
        for (int i = 0; i < 3; i++) {
            a.verificarSenha(Cenario.digitar("13572468"));
        }
        assertEquals(Autenticacao.Resultado.LIBERADO, a.identificar(ADMIN));
    }

    @Test
    public void totalDeAcessosAumentaACadaAutenticacao() throws Exception {
        c.entrar(USER01);
        c.entrar(USER01);
        assertEquals(2, c.banco.buscarUsuario(USER01).getTotalAcessos());
        assertEquals(0, c.banco.buscarUsuario(USER02).getTotalAcessos());
    }

    @Test(expected = IllegalStateException.class)
    public void etapasForaDeOrdemNaoSaoPermitidas() throws Exception {
        a.verificarSenha(Cenario.digitar(Cenario.SENHA_USER01));
    }

    @Test(expected = IllegalStateException.class)
    public void tokenAntesDaSenhaNaoEhPermitido() throws Exception {
        a.identificar(USER01);
        a.verificarToken("123456");
    }

    private void assertBloqueioDe2Minutos(String login) throws Exception {
        int m = c.marca();
        assertEquals(Autenticacao.Resultado.BLOQUEADO, a.identificar(login));
        assertEquals(Cenario.lista(Mensagens.LOGIN_BLOQUEADO), c.mids(m));
        assertEquals(Autenticacao.Etapa.IDENTIFICACAO, a.getEtapa());

        c.agora.addAndGet(Autenticacao.TEMPO_BLOQUEIO_MS - 1000);
        assertEquals(Autenticacao.Resultado.BLOQUEADO, a.identificar(login));

        c.agora.addAndGet(1000);
        assertEquals(Autenticacao.Resultado.LIBERADO, a.identificar(login));
    }

    private String tokenErrado(String login) throws Exception {
        String certo = c.token(login);
        return certo.equals("000000") ? "111111" : "000000";
    }

    private static Object campo(Object objeto, String nome) throws Exception {
        Field f = objeto.getClass().getDeclaredField(nome);
        f.setAccessible(true);
        return f.get(objeto);
    }
}
