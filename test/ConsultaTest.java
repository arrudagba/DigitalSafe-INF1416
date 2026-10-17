import static org.junit.Assert.*;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.junit.*;

//
// Consulta da pasta de arquivos secretos: index/share, politica de controle de
// acesso e decriptacao dos arquivos (7003 a 7021)
public class ConsultaTest {

    private static final String ADMIN  = GeradorPacote.ADMIN;
    private static final String USER01 = GeradorPacote.USER01;
    private static final String USER02 = GeradorPacote.USER02;

    private Cenario c;
    private File pasta;

    @Before
    public void antes() throws Exception {
        c = new Cenario();
        c.cadastrarTodos();
        pasta = c.copiaPastaSegura();
    }

    @After
    public void depois() throws Exception {
        c.close();
    }

    // =====================================================================
    // Listagem e politica de controle de acesso
    // =====================================================================

    @Test
    public void listagemRegistraDecriptacaoEVerificacaoDoIndexEDoShare() throws Exception {
        c.entrar(ADMIN);
        int m = c.marca();
        Consulta.Listagem l = c.sistema.listar(pasta.getPath(), "admin".toCharArray());
        assertTrue(l.mensagem, l.ok());
        assertNull(l.avisoShare);
        assertEquals(Cenario.lista(Mensagens.BOTAO_LISTAR, Mensagens.INDICE_DECRIPTADO, Mensagens.INDICE_VERIFICADO,
                                   Mensagens.SHARE_DECRIPTADO, Mensagens.SHARE_VERIFICADO,
                                   Mensagens.INDICE_LISTA_APRESENTADA, Mensagens.SHARE_LISTA_APRESENTADA), c.mids(m));
    }

    @Test
    public void administradorVeSeusArquivosEOsDoSeuGrupo() throws Exception {
        c.entrar(ADMIN);
        assertEntradas(listar("admin"),
                       "docAdmin.txt=DONO", "relatorioAdmin.txt=DONO");
    }

    @Test
    public void user01VeSeusArquivosOsDoGrupoEOsCompartilhadosComEle() throws Exception {
        c.entrar(USER01);
        assertEntradas(listar("user01"),
                       "docUser01.txt=DONO", "docUser02.txt=GRUPO", "relatorioAdmin.txt=COMPARTILHADO",
                       "assinaturaInvalida.txt=DONO", "envelopeInvalido.txt=DONO");
    }

    @Test
    public void user02VeSeusArquivosOsDoGrupoEOsCompartilhadosComEle() throws Exception {
        c.entrar(USER02);
        assertEntradas(listar("user02"),
                       "docUser01.txt=COMPARTILHADO", "docUser02.txt=DONO",
                       "assinaturaInvalida.txt=GRUPO", "envelopeInvalido.txt=GRUPO");
    }

    @Test
    public void listagemApresentaDonoEGrupoDosArquivos() throws Exception {
        c.entrar(USER02);
        Consulta.Entrada e = listar("user02").entradas.get(0);
        assertEquals("XXYYZZ01", e.nomeCodigo);
        assertEquals("docUser01.txt", e.nomeSecreto);
        assertEquals(USER01, e.dono);
        assertEquals("usuario", e.grupo);
        assertEquals("1", e.idCompartilhamento);
    }

    @Test
    public void totalDeConsultasDoUsuarioAumentaACadaListagem() throws Exception {
        c.entrar(USER01);
        listar("user01");
        c.sistema.listar(pasta.getPath(), "errada".toCharArray());
        assertEquals(2, c.banco.buscarUsuario(USER01).getTotalConsultas());
        assertEquals(0, c.banco.buscarUsuario(USER02).getTotalConsultas());
    }

    @Test
    public void fraseSecretaInvalidaNaoLista() throws Exception {
        c.entrar(USER01);
        int m = c.marca();
        Consulta.Listagem l = c.sistema.listar(pasta.getPath(), "user02".toCharArray());
        assertEquals(Consulta.StatusListagem.FRASE_INVALIDA, l.status);
        assertTrue(l.entradas.isEmpty());
        assertEquals(Cenario.lista(Mensagens.BOTAO_LISTAR, Mensagens.CHAVE_FRASE_INVALIDA), c.mids(m));
    }

    @Test
    public void caminhoDePastaInvalidoRegistra7004() throws Exception {
        c.entrar(USER01);
        for (String caminho : new String[] {"", "/nao/existe", new File(pasta, "index.enc").getPath()}) {
            int m = c.marca();
            Consulta.Listagem l = c.sistema.listar(caminho, "user01".toCharArray());
            assertEquals(Consulta.StatusListagem.CAMINHO_INVALIDO, l.status);
            assertEquals(Cenario.lista(Mensagens.BOTAO_LISTAR, Mensagens.CONSULTA_CAMINHO_INVALIDO), c.mids(m));
        }
    }

    @Test
    public void falhaNaDecriptacaoDoIndiceRegistra7007() throws Exception {
        // envelope do indice gerado para outro destinatario
        copiar("XXYYZZ01.env", "index.env");
        assertFalhaDoIndice(Consulta.StatusListagem.INDICE_FALHA_DECRIPTACAO, Mensagens.INDICE_FALHA_DECRIPTACAO);
    }

    @Test
    public void indiceAusenteRegistra7007() throws Exception {
        assertTrue(new File(pasta, "index.enc").delete());
        assertFalhaDoIndice(Consulta.StatusListagem.INDICE_FALHA_DECRIPTACAO, Mensagens.INDICE_FALHA_DECRIPTACAO);
    }

    @Test
    public void falhaNaVerificacaoDoIndiceRegistra7008() throws Exception {
        alterarByte("index.asd");
        assertFalhaDoIndice(Consulta.StatusListagem.INDICE_FALHA_VERIFICACAO, Mensagens.INDICE_FALHA_VERIFICACAO);
    }

    @Test
    public void indiceAssinadoPorOutroUsuarioRegistra7008() throws Exception {
        copiar("XXYYZZ02.asd", "index.asd");
        assertFalhaDoIndice(Consulta.StatusListagem.INDICE_FALHA_VERIFICACAO, Mensagens.INDICE_FALHA_VERIFICACAO);
    }

    @Test
    public void falhaNaDecriptacaoDoShareRegistra7012ELista0Indice() throws Exception {
        copiar("XXYYZZ02.env", "share.env");
        c.entrar(USER01);
        int m = c.marca();
        Consulta.Listagem l = listar("user01");
        assertNotNull(l.avisoShare);
        assertEquals(Cenario.lista(Mensagens.BOTAO_LISTAR, Mensagens.INDICE_DECRIPTADO, Mensagens.INDICE_VERIFICADO,
                                   Mensagens.SHARE_FALHA_DECRIPTACAO, Mensagens.INDICE_LISTA_APRESENTADA), c.mids(m));
        // sem o share, o arquivo compartilhado pelo admin nao aparece
        assertEntradas(l, "docUser01.txt=DONO", "docUser02.txt=GRUPO",
                       "assinaturaInvalida.txt=DONO", "envelopeInvalido.txt=DONO");
    }

    @Test
    public void falhaNaVerificacaoDoShareRegistra7013() throws Exception {
        alterarByte("share.asd");
        c.entrar(USER02);
        int m = c.marca();
        Consulta.Listagem l = listar("user02");
        assertNotNull(l.avisoShare);
        assertEquals(Cenario.lista(Mensagens.BOTAO_LISTAR, Mensagens.INDICE_DECRIPTADO, Mensagens.INDICE_VERIFICADO,
                                   Mensagens.SHARE_DECRIPTADO, Mensagens.SHARE_FALHA_VERIFICACAO,
                                   Mensagens.INDICE_LISTA_APRESENTADA), c.mids(m));
        assertEntradas(l, "docUser01.txt=GRUPO", "docUser02.txt=DONO",
                       "assinaturaInvalida.txt=GRUPO", "envelopeInvalido.txt=GRUPO");
    }

    // =====================================================================
    // Decriptacao dos arquivos secretos
    // =====================================================================

    @Test
    public void arquivoDoDonoEhDecriptadoVerificadoEGravadoComONomeSecreto() throws Exception {
        c.entrar(USER01);
        Consulta.Listagem l = listar("user01");
        int m = c.marca();
        Consulta.ResultadoArquivo r = c.sistema.decriptar(l, entrada(l, "docUser01.txt"));
        assertEquals(r.mensagem, Consulta.StatusArquivo.OK, r.status);
        assertEquals(Cenario.lista(Mensagens.ARQUIVO_SELECIONADO, Mensagens.ARQUIVO_ACESSO_PERMITIDO,
                                   Mensagens.ARQUIVO_DECRIPTADO, Mensagens.ARQUIVO_VERIFICADO), c.mids(m));
        assertEquals(new File(pasta, "docUser01.txt"), r.arquivoGravado);
        assertEquals("Documento secreto do user01 (compartilhado com o user02).", ler(r.arquivoGravado));
        // o registro identifica o usuario e o arquivo selecionado
        Object[] ultimo = c.ultimoRegistro();
        assertEquals(c.banco.buscarUsuario(USER01).getUid(), ultimo[1]);
        assertEquals("docUser01.txt", ultimo[3]);
    }

    @Test
    public void administradorDecriptaSeuArquivo() throws Exception {
        c.entrar(ADMIN);
        Consulta.Listagem l = listar("admin");
        Consulta.ResultadoArquivo r = c.sistema.decriptar(l, entrada(l, "docAdmin.txt"));
        assertEquals(Consulta.StatusArquivo.OK, r.status);
        assertEquals("Documento secreto do administrador.", ler(r.arquivoGravado));
    }

    @Test
    public void arquivoCompartilhadoEhDecriptadoComOEnvelopeShr() throws Exception {
        c.entrar(USER01);
        Consulta.Listagem l = listar("user01");
        Consulta.ResultadoArquivo r = c.sistema.decriptar(l, entrada(l, "relatorioAdmin.txt"));
        assertEquals(r.mensagem, Consulta.StatusArquivo.OK, r.status);
        assertEquals("Relatorio do administrador compartilhado com o user01.", ler(r.arquivoGravado));

        c.sistema.encerrarSessao();
        c.entrar(USER02);
        l = listar("user02");
        r = c.sistema.decriptar(l, entrada(l, "docUser01.txt"));
        assertEquals(r.mensagem, Consulta.StatusArquivo.OK, r.status);
        assertEquals("Documento secreto do user01 (compartilhado com o user02).", ler(r.arquivoGravado));
    }

    @Test
    public void envelopeShrComOutrosSeparadoresDeNome() throws Exception {
        for (String nome : new String[] {"XXYYZZ032.shr", "XXYYZZ03-2.shr", "XXYYZZ03.2.shr"}) {
            File atual = new File(pasta, "XXYYZZ03_2.shr");
            File novo = new File(pasta, nome);
            Files.move(atual.toPath(), novo.toPath());
            c.entrar(USER01);
            Consulta.Listagem l = listar("user01");
            assertEquals(nome, Consulta.StatusArquivo.OK, c.sistema.decriptar(l, entrada(l, "relatorioAdmin.txt")).status);
            c.sistema.encerrarSessao();
            Files.move(novo.toPath(), atual.toPath());
        }
    }

    @Test
    public void arquivoApenasDoGrupoTemAcessoNegado() throws Exception {
        c.entrar(USER01);
        Consulta.Listagem l = listar("user01");
        int m = c.marca();
        Consulta.ResultadoArquivo r = c.sistema.decriptar(l, entrada(l, "docUser02.txt"));
        assertEquals(Consulta.StatusArquivo.ACESSO_NEGADO, r.status);
        assertTrue(r.mensagem.contains("permissão"));
        assertEquals(Cenario.lista(Mensagens.ARQUIVO_SELECIONADO, Mensagens.ARQUIVO_ACESSO_NEGADO), c.mids(m));
        assertFalse(new File(pasta, "docUser02.txt").exists());
    }

    @Test
    public void falhaNaDecriptacaoDoArquivoRegistra7020() throws Exception {
        c.entrar(USER01);
        Consulta.Listagem l = listar("user01");
        int m = c.marca();
        Consulta.ResultadoArquivo r = c.sistema.decriptar(l, entrada(l, "envelopeInvalido.txt"));
        assertEquals(Consulta.StatusArquivo.FALHA_DECRIPTACAO, r.status);
        assertEquals(Cenario.lista(Mensagens.ARQUIVO_SELECIONADO, Mensagens.ARQUIVO_ACESSO_PERMITIDO,
                                   Mensagens.ARQUIVO_FALHA_DECRIPTACAO), c.mids(m));
        assertFalse(new File(pasta, "envelopeInvalido.txt").exists());
    }

    @Test
    public void arquivoCifradoAlteradoNaoEhGravado() throws Exception {
        alterarByte("XXYYZZ01.enc");
        c.entrar(USER01);
        Consulta.Listagem l = listar("user01");
        Consulta.ResultadoArquivo r = c.sistema.decriptar(l, entrada(l, "docUser01.txt"));
        assertTrue(r.status == Consulta.StatusArquivo.FALHA_DECRIPTACAO
                || r.status == Consulta.StatusArquivo.FALHA_VERIFICACAO);
        assertFalse(new File(pasta, "docUser01.txt").exists());
    }

    @Test
    public void falhaNaVerificacaoDoArquivoRegistra7021ENaoGrava() throws Exception {
        c.entrar(USER01);
        Consulta.Listagem l = listar("user01");
        int m = c.marca();
        Consulta.ResultadoArquivo r = c.sistema.decriptar(l, entrada(l, "assinaturaInvalida.txt"));
        assertEquals(Consulta.StatusArquivo.FALHA_VERIFICACAO, r.status);
        assertEquals(Cenario.lista(Mensagens.ARQUIVO_SELECIONADO, Mensagens.ARQUIVO_ACESSO_PERMITIDO,
                                   Mensagens.ARQUIVO_DECRIPTADO, Mensagens.ARQUIVO_FALHA_VERIFICACAO), c.mids(m));
        assertFalse(new File(pasta, "assinaturaInvalida.txt").exists());
    }

    @Test
    public void donoNaoCadastradoImpedeAVerificacaoDaAutenticidade() throws Exception {
        GeradorPacote.Pacote p = c.p();
        byte[] semente = GeradorPacote.protegerArquivo(pasta, "XXYYZZ09", texto("orfao"),
                                                       p.user02.par.getPublic(), p.user02.par.getPrivate());
        GeradorPacote.criarEnvelope(new File(pasta, "XXYYZZ09_7.shr"), semente, p.user01.par.getPublic());
        reescreverIndice("XXYYZZ09 orfao.txt ninguem@inf1416.puc-rio.br usuario\n", "XXYYZZ09 7 " + USER01 + "\n");
        c.entrar(USER01);
        Consulta.Listagem l = listar("user01");
        assertEquals(Consulta.StatusArquivo.FALHA_VERIFICACAO,
                     c.sistema.decriptar(l, entrada(l, "orfao.txt")).status);
    }

    @Test
    public void nomeSecretoComCaminhoNaoGravaForaDaPasta() throws Exception {
        GeradorPacote.Pacote p = c.p();
        GeradorPacote.protegerArquivo(pasta, "XXYYZZ08", texto("invasao"),
                                      p.user01.par.getPublic(), p.user01.par.getPrivate());
        reescreverIndice("XXYYZZ08 ../fora.txt " + USER01 + " usuario\n", "");
        c.entrar(USER01);
        Consulta.Listagem l = listar("user01");
        Consulta.ResultadoArquivo r = c.sistema.decriptar(l, entrada(l, "../fora.txt"));
        assertEquals(Consulta.StatusArquivo.ACESSO_NEGADO, r.status);
        assertFalse(new File(pasta.getParentFile(), "fora.txt").exists());
    }

    @Test
    public void indiceVazioListaNenhumArquivo() throws Exception {
        reescreverIndice("", "");
        c.entrar(USER01);
        Consulta.Listagem l = listar("user01");
        assertTrue(l.ok());
        assertTrue(l.entradas.isEmpty());
    }

    // =====================================================================
    // Formato dos arquivos index e share
    // =====================================================================

    @Test
    public void linhasDoIndiceSeparadasPorEspacoEFimDeLinha() {
        List<String[]> linhas = Consulta.linhas(texto("A B c@d.com usuario\r\n\nC D e@f.com administrador\n  \n"));
        assertEquals(2, linhas.size());
        assertArrayEquals(new String[] {"A", "B", "c@d.com", "usuario"}, linhas.get(0));
        assertArrayEquals(new String[] {"C", "D", "e@f.com", "administrador"}, linhas.get(1));
    }

    @Test
    public void grupoDoArquivoComparadoSemAcentosEMaiusculas() {
        assertTrue(Consulta.mesmoGrupo("usuario", "Usuário"));
        assertTrue(Consulta.mesmoGrupo("ADMINISTRADOR", "Administrador"));
        assertFalse(Consulta.mesmoGrupo("administrador", "Usuário"));
    }

    @Test
    public void linhasMalFormadasDoIndiceSaoIgnoradas() throws Exception {
        Usuario u = c.banco.buscarUsuario(USER01);
        List<Consulta.Entrada> e = Consulta.filtrar(u, Consulta.linhas(texto("X1 a.txt\nX2 b.txt " + USER01 + " usuario\n")),
                                                    Collections.<String[]>emptyList());
        assertEquals(1, e.size());
        assertEquals("b.txt", e.get(0).nomeSecreto);
    }

    // =====================================================================
    // Auxiliares
    // =====================================================================

    private Consulta.Listagem listar(String frase) throws Exception {
        Consulta.Listagem l = c.sistema.listar(pasta.getPath(), frase.toCharArray());
        assertTrue(l.status + ": " + l.mensagem, l.ok());
        return l;
    }

    private void assertFalhaDoIndice(Consulta.StatusListagem status, int mid) throws Exception {
        c.entrar(USER01);
        int m = c.marca();
        Consulta.Listagem l = c.sistema.listar(pasta.getPath(), "user01".toCharArray());
        assertEquals(status, l.status);
        assertTrue(l.entradas.isEmpty());
        List<Integer> esperado = mid == Mensagens.INDICE_FALHA_DECRIPTACAO
            ? Cenario.lista(Mensagens.BOTAO_LISTAR, mid)
            : Cenario.lista(Mensagens.BOTAO_LISTAR, Mensagens.INDICE_DECRIPTADO, mid);
        assertEquals(esperado, c.mids(m));
    }

    private static void assertEntradas(Consulta.Listagem l, String... esperadas) {
        List<String> obtidas = new ArrayList<String>();
        for (Consulta.Entrada e : l.entradas) {
            obtidas.add(e.nomeSecreto + "=" + e.acesso);
        }
        assertEquals(Arrays.asList(esperadas), obtidas);
    }

    private static Consulta.Entrada entrada(Consulta.Listagem l, String nomeSecreto) {
        for (Consulta.Entrada e : l.entradas) {
            if (e.nomeSecreto.equals(nomeSecreto)) {
                return e;
            }
        }
        throw new AssertionError(nomeSecreto + " nao esta na listagem");
    }

    private void copiar(String origem, String destino) throws Exception {
        Files.copy(new File(pasta, origem).toPath(), new File(pasta, destino).toPath(),
                   StandardCopyOption.REPLACE_EXISTING);
    }

    private void alterarByte(String nome) throws Exception {
        Path arquivo = new File(pasta, nome).toPath();
        byte[] dados = Files.readAllBytes(arquivo);
        dados[dados.length / 2] ^= 0x01;
        Files.write(arquivo, dados);
    }

    //
    // novo index/share protegidos com as chaves do administrador
    private void reescreverIndice(String index, String share) throws Exception {
        GeradorPacote.Pacote p = c.p();
        GeradorPacote.protegerArquivo(pasta, "index", texto(index), p.admin.par.getPublic(), p.admin.par.getPrivate());
        GeradorPacote.protegerArquivo(pasta, "share", texto(share), p.admin.par.getPublic(), p.admin.par.getPrivate());
    }

    private static byte[] texto(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static String ler(File f) throws Exception {
        return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
    }
}
