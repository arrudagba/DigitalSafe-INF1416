import java.util.*;

//
// Tabela de Mensagens de Registro (anexo do enunciado). Os textos sao gravados
// na tabela Mensagens do banco de dados; a tabela Registros guarda apenas o MID.
public final class Mensagens {

    public static final int SISTEMA_INICIADO                 = 1001;
    public static final int SISTEMA_ENCERRADO                = 1002;
    public static final int SESSAO_INICIADA                  = 1003;
    public static final int SESSAO_ENCERRADA                 = 1004;
    public static final int PARTIDA_CADASTRO_ADMIN           = 1005;
    public static final int PARTIDA_OPERACAO_NORMAL          = 1006;

    public static final int ETAPA1_INICIADA                  = 2001;
    public static final int ETAPA1_ENCERRADA                 = 2002;
    public static final int LOGIN_LIBERADO                   = 2003;
    public static final int LOGIN_BLOQUEADO                  = 2004;
    public static final int LOGIN_NAO_IDENTIFICADO           = 2005;

    public static final int ETAPA2_INICIADA                  = 3001;
    public static final int ETAPA2_ENCERRADA                 = 3002;
    public static final int SENHA_OK                         = 3003;
    public static final int SENHA_ERRO1                      = 3004;
    public static final int SENHA_ERRO2                      = 3005;
    public static final int SENHA_ERRO3                      = 3006;
    public static final int SENHA_BLOQUEIO                   = 3007;

    public static final int ETAPA3_INICIADA                  = 4001;
    public static final int ETAPA3_ENCERRADA                 = 4002;
    public static final int TOKEN_OK                         = 4003;
    public static final int TOKEN_ERRO1                      = 4004;
    public static final int TOKEN_ERRO2                      = 4005;
    public static final int TOKEN_ERRO3                      = 4006;
    public static final int TOKEN_BLOQUEIO                   = 4007;

    public static final int TELA_PRINCIPAL                   = 5001;
    public static final int MENU_OPCAO1                      = 5002;
    public static final int MENU_OPCAO2                      = 5003;
    public static final int MENU_OPCAO3                      = 5004;

    public static final int TELA_CADASTRO                    = 6001;
    public static final int BOTAO_CADASTRAR                  = 6002;
    public static final int CADASTRO_SENHA_INVALIDA          = 6003;
    public static final int CADASTRO_CERTIFICADO_INVALIDO    = 6004;
    public static final int CHAVE_CAMINHO_INVALIDO           = 6005;
    public static final int CHAVE_FRASE_INVALIDA             = 6006;
    public static final int CHAVE_ASSINATURA_INVALIDA        = 6007;
    public static final int CONFIRMACAO_ACEITA               = 6008;
    public static final int CONFIRMACAO_REJEITADA            = 6009;
    public static final int BOTAO_VOLTAR_CADASTRO            = 6010;

    public static final int TELA_CONSULTA                    = 7001;
    public static final int BOTAO_VOLTAR_CONSULTA            = 7002;
    public static final int BOTAO_LISTAR                     = 7003;
    public static final int CONSULTA_CAMINHO_INVALIDO        = 7004;
    public static final int INDICE_DECRIPTADO                = 7005;
    public static final int INDICE_VERIFICADO                = 7006;
    public static final int INDICE_FALHA_DECRIPTACAO         = 7007;
    public static final int INDICE_FALHA_VERIFICACAO         = 7008;
    public static final int INDICE_LISTA_APRESENTADA         = 7009;
    public static final int SHARE_DECRIPTADO                 = 7010;
    public static final int SHARE_VERIFICADO                 = 7011;
    public static final int SHARE_FALHA_DECRIPTACAO          = 7012;
    public static final int SHARE_FALHA_VERIFICACAO          = 7013;
    public static final int SHARE_LISTA_APRESENTADA          = 7014;
    public static final int ARQUIVO_SELECIONADO              = 7015;
    public static final int ARQUIVO_ACESSO_PERMITIDO         = 7016;
    public static final int ARQUIVO_ACESSO_NEGADO            = 7017;
    public static final int ARQUIVO_DECRIPTADO               = 7018;
    public static final int ARQUIVO_VERIFICADO               = 7019;
    public static final int ARQUIVO_FALHA_DECRIPTACAO        = 7020;
    public static final int ARQUIVO_FALHA_VERIFICACAO        = 7021;

    public static final int TELA_SAIDA                       = 8001;
    public static final int BOTAO_ENCERRAR_SESSAO            = 8002;
    public static final int BOTAO_ENCERRAR_SISTEMA           = 8003;
    public static final int BOTAO_VOLTAR_SAIDA               = 8004;

    public static final String LOGIN_NAME = "<login_name>";
    public static final String ARQ_NAME   = "<arq_name>";

    public static final Map<Integer, String> TABELA;

    static {
        Map<Integer, String> t = new LinkedHashMap<Integer, String>();
        t.put(1001, "Sistema iniciado.");
        t.put(1002, "Sistema encerrado.");
        t.put(1003, "Sessão iniciada para <login_name>.");
        t.put(1004, "Sessão encerrada para <login_name>.");
        t.put(1005, "Partida do sistema iniciada para cadastro do administrador.");
        t.put(1006, "Partida do sistema iniciada para operação normal pelos usuários.");
        t.put(2001, "Autenticação etapa 1 iniciada.");
        t.put(2002, "Autenticação etapa 1 encerrada.");
        t.put(2003, "Login name <login_name> identificado com acesso liberado.");
        t.put(2004, "Login name <login_name> identificado com acesso bloqueado.");
        t.put(2005, "Login name <login_name> não identificado.");
        t.put(3001, "Autenticação etapa 2 iniciada para <login_name>.");
        t.put(3002, "Autenticação etapa 2 encerrada para <login_name>.");
        t.put(3003, "Senha pessoal verificada positivamente para <login_name>.");
        t.put(3004, "Primeiro erro da senha pessoal contabilizado para <login_name>.");
        t.put(3005, "Segundo erro da senha pessoal contabilizado para <login_name>.");
        t.put(3006, "Terceiro erro da senha pessoal contabilizado para <login_name>.");
        t.put(3007, "Acesso do usuario <login_name> bloqueado pela autenticação etapa 2.");
        t.put(4001, "Autenticação etapa 3 iniciada para <login_name>.");
        t.put(4002, "Autenticação etapa 3 encerrada para <login_name>.");
        t.put(4003, "Token verificado positivamente para <login_name>.");
        t.put(4004, "Primeiro erro de token contabilizado para <login_name>.");
        t.put(4005, "Segundo erro de token contabilizado para <login_name>.");
        t.put(4006, "Terceiro erro de token contabilizado para <login_name>.");
        t.put(4007, "Acesso do usuario <login_name> bloqueado pela autenticação etapa 3.");
        t.put(5001, "Tela principal apresentada para <login_name>.");
        t.put(5002, "Opção 1 do menu principal selecionada por <login_name>.");
        t.put(5003, "Opção 2 do menu principal selecionada por <login_name>.");
        t.put(5004, "Opção 3 do menu principal selecionada por <login_name>.");
        t.put(6001, "Tela de cadastro apresentada para <login_name>.");
        t.put(6002, "Botão cadastrar pressionado por <login_name>.");
        t.put(6003, "Senha pessoal inválida fornecida por <login_name>.");
        t.put(6004, "Caminho do certificado digital inválido fornecido por <login_name>.");
        t.put(6005, "Chave privada verificada negativamente para <login_name> (caminho inválido).");
        t.put(6006, "Chave privada verificada negativamente para <login_name> (frase secreta inválida).");
        t.put(6007, "Chave privada verificada negativamente para <login_name> (assinatura digital inválida).");
        t.put(6008, "Confirmação de dados aceita por <login_name>.");
        t.put(6009, "Confirmação de dados rejeitada por <login_name>.");
        t.put(6010, "Botão voltar de cadastro para o menu principal pressionado por <login_name>.");
        t.put(7001, "Tela de consulta de arquivos secretos apresentada para <login_name>.");
        t.put(7002, "Botão voltar de consulta para o menu principal pressionado por <login_name>.");
        t.put(7003, "Botão Listar de consulta pressionado por <login_name>.");
        t.put(7004, "Caminho de pasta inválido fornecido por <login_name>.");
        t.put(7005, "Arquivo de índice decriptado com sucesso para <login_name>.");
        t.put(7006, "Arquivo de índice verificado (integridade e autenticidade) com sucesso para <login_name>.");
        t.put(7007, "Falha na decriptação do arquivo de índice para <login_name>.");
        t.put(7008, "Falha na verificação (integridade e autenticidade) do arquivo de índice para <login_name>.");
        t.put(7009, "Lista de arquivos presentes no índice apresentada para <login_name>.");
        t.put(7010, "Arquivo de share decriptado com sucesso para <login_name>.");
        t.put(7011, "Arquivo de share verificado (integridade e autenticidade) com sucesso para <login_name>.");
        t.put(7012, "Falha na decriptação do arquivo de share para <login_name>.");
        t.put(7013, "Falha na verificação (integridade e autenticidade) do arquivo de share para <login_name>.");
        t.put(7014, "Lista de arquivos presentes no share apresentada para <login_name>.");
        t.put(7015, "Arquivo <arq_name> selecionado por <login_name> para decriptação.");
        t.put(7016, "Acesso permitido ao arquivo <arq_name> para <login_name>.");
        t.put(7017, "Acesso negado ao arquivo <arq_name> para <login_name>.");
        t.put(7018, "Arquivo <arq_name> decriptado com sucesso para <login_name>.");
        t.put(7019, "Arquivo <arq_name> verificado (integridade e autenticidade) com sucesso para <login_name>.");
        t.put(7020, "Falha na decriptação do arquivo <arq_name> para <login_name>.");
        t.put(7021, "Falha na verificação (integridade e autenticidade) do arquivo <arq_name> para <login_name>.");
        t.put(8001, "Tela de saída apresentada para <login_name>.");
        t.put(8002, "Botão encerrar sessão pressionado por <login_name>.");
        t.put(8003, "Botão encerrar sistema pressionado por <login_name>.");
        t.put(8004, "Botão voltar de sair para o menu principal pressionado por <login_name>.");
        TABELA = Collections.unmodifiableMap(t);
    }

    private Mensagens() {
    }

    //
    // substitui <login_name> e <arq_name> no texto de uma mensagem
    public static String formatar(String texto, String loginName, String arqName) {
        String s = texto;
        s = s.replace(LOGIN_NAME, loginName != null ? loginName : "-");
        s = s.replace(ARQ_NAME, arqName != null ? arqName : "-");
        return s;
    }
}
