// Gabriel de Barros Arruda - 2311723
// Erica Oliveira Regnier - 2211893

import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.function.LongSupplier;

public class Sistema implements AutoCloseable {

    public enum Partida { CADASTRO_ADMINISTRADOR, OPERACAO_NORMAL }

    private final Banco banco;
    private final Log log;
    private final Autenticacao autenticacao;
    private final Cadastro cadastro;
    private final Consulta consulta;

    private char[] fraseAdministrador;
    private Usuario usuarioSessao;
    private boolean encerrado;

    public Sistema(String caminhoBanco) throws SQLException {
        this(new Banco(caminhoBanco), System::currentTimeMillis);
    }

    Sistema(Banco banco, LongSupplier relogio) {
        this.banco = banco;
        this.log = new Log(banco, relogio);
        this.autenticacao = new Autenticacao(banco, log, relogio);
        this.cadastro = new Cadastro(banco, log);
        this.consulta = new Consulta(banco, log);
    }

    public Banco getBanco()               { return banco; }
    public Log getLog()                   { return log; }
    public Autenticacao getAutenticacao() { return autenticacao; }
    public Cadastro getCadastro()         { return cadastro; }
    public Consulta getConsulta()         { return consulta; }
    public Usuario getUsuarioSessao()     { return usuarioSessao; }

    public Partida iniciar() throws SQLException {
        log.registrar(Mensagens.SISTEMA_INICIADO);
        if (banco.totalUsuarios() == 0) {
            log.registrar(Mensagens.PARTIDA_CADASTRO_ADMIN);
            return Partida.CADASTRO_ADMINISTRADOR;
        }
        log.registrar(Mensagens.PARTIDA_OPERACAO_NORMAL);
        return Partida.OPERACAO_NORMAL;
    }

    public boolean validarFraseAdministrador(char[] frase) throws SQLException {
        Usuario admin = banco.administradorDoSistema();
        if (admin == null || frase == null) {
            return false;
        }
        try {
            X509Certificate certificado = CriptoUtil.certificadoDePem(banco.certificadoPem(admin.kid));
            CriptoUtil.ResultadoChave r = CriptoUtil.validarChavePrivada(banco.chavePrivadaCifrada(admin.kid),
                                                                         frase, certificado, CriptoUtil.TESTE_CADASTRO);
            if (r.status != CriptoUtil.StatusChave.OK) {
                return false;
            }
        } catch (java.security.cert.CertificateException e) {
            return false;
        }
        definirFraseAdministrador(frase);
        return true;
    }

    public void definirFraseAdministrador(char[] frase) {
        apagarFraseAdministrador();
        fraseAdministrador = frase.clone();
    }

    char[] getFraseAdministrador() {
        return fraseAdministrador;
    }

    public void iniciarAutenticacao() {
        usuarioSessao = null;
        autenticacao.iniciar();
    }

    public void iniciarSessao() {
        usuarioSessao = autenticacao.getUsuario();
        autenticacao.limpar();
    }

    public void telaPrincipal()            { log.registrar(Mensagens.TELA_PRINCIPAL, usuarioSessao); }
    public void opcaoCadastrar()           { log.registrar(Mensagens.MENU_OPCAO1, usuarioSessao); }
    public void opcaoConsultar()           { log.registrar(Mensagens.MENU_OPCAO2, usuarioSessao); }
    public void opcaoSair()                { log.registrar(Mensagens.MENU_OPCAO3, usuarioSessao); }
    public void telaCadastro()             { log.registrar(Mensagens.TELA_CADASTRO, usuarioSessao); }
    public void voltarDeCadastrar()        { log.registrar(Mensagens.BOTAO_VOLTAR_CADASTRO, usuarioSessao); }
    public void telaConsulta()             { log.registrar(Mensagens.TELA_CONSULTA, usuarioSessao); }
    public void voltarDeConsultar()        { log.registrar(Mensagens.BOTAO_VOLTAR_CONSULTA, usuarioSessao); }
    public void telaSaida()                { log.registrar(Mensagens.TELA_SAIDA, usuarioSessao); }
    public void voltarDeSair()             { log.registrar(Mensagens.BOTAO_VOLTAR_SAIDA, usuarioSessao); }

    public void encerrarSessao() {
        log.registrar(Mensagens.BOTAO_ENCERRAR_SESSAO, usuarioSessao);
        finalizarSessao();
        iniciarAutenticacao();
    }

    public void botaoEncerrarSistema() {
        log.registrar(Mensagens.BOTAO_ENCERRAR_SISTEMA, usuarioSessao);
        encerrar();
    }

    private void finalizarSessao() {
        if (usuarioSessao != null) {
            log.registrar(Mensagens.SESSAO_ENCERRADA, usuarioSessao);
            usuarioSessao = null;
        }
    }

    public void encerrar() {
        if (encerrado) {
            return;
        }
        finalizarSessao();
        autenticacao.limpar();
        apagarFraseAdministrador();
        log.registrar(Mensagens.SISTEMA_ENCERRADO);
        encerrado = true;
    }

    private void apagarFraseAdministrador() {
        if (fraseAdministrador != null) {
            Arrays.fill(fraseAdministrador, '\0');
            fraseAdministrador = null;
        }
    }

    public int totalUsuarios() throws SQLException {
        return banco.totalUsuarios();
    }

    public Usuario atualizarUsuarioSessao() throws SQLException {
        if (usuarioSessao != null) {
            usuarioSessao = banco.buscarUsuario(usuarioSessao.uid);
        }
        return usuarioSessao;
    }

    public Cadastro.Preparacao prepararCadastro(Cadastro.Formulario f) throws SQLException {
        return cadastro.preparar(f, usuarioSessao);
    }

    public Consulta.Listagem listar(String caminhoPasta, char[] fraseUsuario) throws SQLException {
        return consulta.listar(usuarioSessao, caminhoPasta, fraseUsuario, fraseAdministrador);
    }

    public Consulta.ResultadoArquivo decriptar(Consulta.Listagem listagem, Consulta.Entrada entrada)
            throws SQLException {
        return consulta.decriptar(usuarioSessao, listagem, entrada);
    }

    @Override
    public void close() throws SQLException {
        encerrar();
        banco.close();
    }
}
