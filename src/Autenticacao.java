// Gabriel de Barros Arruda - 2311723
// Erica Oliveira Regnier - 2211893

import java.sql.SQLException;
import java.util.*;
import java.util.function.LongSupplier;

public class Autenticacao {

    public static final long TEMPO_BLOQUEIO_MS = 2 * 60 * 1000;
    public static final int  MAXIMO_ERROS      = 3;

    public enum Etapa { IDENTIFICACAO, SENHA, TOKEN, AUTENTICADO }

    public enum Resultado {
        LIBERADO,
        NAO_IDENTIFICADO,
        BLOQUEADO,
        SENHA_OK,
        SENHA_INVALIDA,
        TOKEN_OK,
        TOKEN_INVALIDO
    }

    private static final int[] ERROS_SENHA = {Mensagens.SENHA_ERRO1, Mensagens.SENHA_ERRO2, Mensagens.SENHA_ERRO3};
    private static final int[] ERROS_TOKEN = {Mensagens.TOKEN_ERRO1, Mensagens.TOKEN_ERRO2, Mensagens.TOKEN_ERRO3};

    private final Banco banco;
    private final Log log;
    private final LongSupplier relogio;

    private Etapa etapa = Etapa.IDENTIFICACAO;
    private Usuario usuario;
    private char[] senhaVerificada;

    public Autenticacao(Banco banco, Log log, LongSupplier relogio) {
        this.banco = banco;
        this.log = log;
        this.relogio = relogio;
    }

    public Etapa getEtapa() {
        return etapa;
    }

    public Usuario getUsuario() {
        return usuario;
    }

    public void iniciar() {
        limpar();
        etapa = Etapa.IDENTIFICACAO;
        log.registrar(Mensagens.ETAPA1_INICIADA);
    }

    public Resultado identificar(String loginName) throws SQLException {
        exigirEtapa(Etapa.IDENTIFICACAO);
        String login = loginName == null ? "" : loginName.trim();
        Usuario u = CriptoUtil.emailValido(login) ? banco.buscarUsuario(login) : null;
        if (u == null) {
            log.registrar(Mensagens.LOGIN_NAO_IDENTIFICADO, login);
            return Resultado.NAO_IDENTIFICADO;
        }
        if (u.isBloqueado(relogio.getAsLong())) {
            log.registrar(Mensagens.LOGIN_BLOQUEADO, u);
            return Resultado.BLOQUEADO;
        }
        log.registrar(Mensagens.LOGIN_LIBERADO, u);
        log.registrar(Mensagens.ETAPA1_ENCERRADA);
        usuario = u;
        etapa = Etapa.SENHA;
        log.registrar(Mensagens.ETAPA2_INICIADA, usuario);
        return Resultado.LIBERADO;
    }

    public Resultado verificarSenha(List<char[]> paresPressionados) throws SQLException {
        exigirEtapa(Etapa.SENHA);
        char[] senha = Senha.descobrir(usuario.senha, paresPressionados);
        if (senha != null) {
            senhaVerificada = senha;
            banco.definirErrosSenha(usuario.uid, 0);
            usuario.errosSenha = 0;
            log.registrar(Mensagens.SENHA_OK, usuario);
            log.registrar(Mensagens.ETAPA2_ENCERRADA, usuario);
            etapa = Etapa.TOKEN;
            log.registrar(Mensagens.ETAPA3_INICIADA, usuario);
            return Resultado.SENHA_OK;
        }
        int erros = usuario.errosSenha + 1;
        log.registrar(ERROS_SENHA[erros - 1], usuario);
        if (erros >= MAXIMO_ERROS) {
            bloquear(Mensagens.SENHA_BLOQUEIO, Mensagens.ETAPA2_ENCERRADA);
            return Resultado.BLOQUEADO;
        }
        banco.definirErrosSenha(usuario.uid, erros);
        usuario.errosSenha = erros;
        return Resultado.SENHA_INVALIDA;
    }

    public Resultado verificarToken(String codigo) throws SQLException {
        exigirEtapa(Etapa.TOKEN);
        if (tokenValido(codigo)) {
            banco.definirErrosToken(usuario.uid, 0);
            usuario.errosToken = 0;
            log.registrar(Mensagens.TOKEN_OK, usuario);
            log.registrar(Mensagens.ETAPA3_ENCERRADA, usuario);
            banco.incrementarAcessos(usuario.uid);
            usuario.totalAcessos++;
            apagarSenha();
            etapa = Etapa.AUTENTICADO;
            log.registrar(Mensagens.SESSAO_INICIADA, usuario);
            return Resultado.TOKEN_OK;
        }
        int erros = usuario.errosToken + 1;
        log.registrar(ERROS_TOKEN[erros - 1], usuario);
        if (erros >= MAXIMO_ERROS) {
            bloquear(Mensagens.TOKEN_BLOQUEIO, Mensagens.ETAPA3_ENCERRADA);
            return Resultado.BLOQUEADO;
        }
        banco.definirErrosToken(usuario.uid, erros);
        usuario.errosToken = erros;
        return Resultado.TOKEN_INVALIDO;
    }

    private boolean tokenValido(String codigo) {
        try {
            byte[] base32 = CriptoUtil.decifrarAES(CriptoUtil.chaveAES(senhaVerificada), usuario.chaveTotp);
            try {
                return new TOTP(new String(base32, "US-ASCII"), 30).validateCode(codigo);
            } finally {
                Arrays.fill(base32, (byte) 0);
            }
        } catch (Exception e) {
            return false;
        }
    }

    private void bloquear(int midBloqueio, int midEtapaEncerrada) throws SQLException {
        banco.bloquear(usuario.uid, relogio.getAsLong() + TEMPO_BLOQUEIO_MS);
        log.registrar(midBloqueio, usuario);
        log.registrar(midEtapaEncerrada, usuario);
        iniciar();
    }

    private void exigirEtapa(Etapa esperada) {
        if (etapa != esperada) {
            throw new IllegalStateException("Etapa atual: " + etapa + "; esperada: " + esperada);
        }
    }

    private void apagarSenha() {
        if (senhaVerificada != null) {
            Arrays.fill(senhaVerificada, '\0');
            senhaVerificada = null;
        }
    }

    public void limpar() {
        apagarSenha();
        usuario = null;
    }
}
