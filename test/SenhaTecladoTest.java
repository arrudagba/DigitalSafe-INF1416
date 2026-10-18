// Gabriel de Barros Arruda - 2311723
// Erica Oliveira Regnier - 2211893

import static org.junit.Assert.*;

import java.util.*;
import org.junit.*;

public class SenhaTecladoTest {

    @Test
    public void senhasDeOitoNoveOuDezDigitosSaoValidas() {
        for (String s : new String[] {"13572468", "135724680", "1357246809", "01010101", "9753186420"}) {
            assertTrue(s, Senha.formatoValido(s.toCharArray()));
        }
    }

    @Test
    public void senhasComTamanhoInvalidoSaoRejeitadas() {
        for (String s : new String[] {"", "1", "1357246", "13572468091", "135724680913"}) {
            assertFalse(s, Senha.formatoValido(s.toCharArray()));
        }
        assertFalse(Senha.formatoValido(null));
    }

    @Test
    public void senhasComCaracteresQueNaoSaoDigitosSaoRejeitadas() {
        for (String s : new String[] {"1357246a", "13572 468", "1357-2468", "１３５７２４６８", "abcdefgh"}) {
            assertFalse(s, Senha.formatoValido(s.toCharArray()));
        }
    }

    @Test
    public void senhasComNumerosRepetidosEmSequenciaSaoRejeitadas() {
        for (String s : new String[] {"11111111", "11357246", "13572466", "1355724680", "0000000000"}) {
            assertFalse(s, Senha.formatoValido(s.toCharArray()));
        }
    }

    @Test
    public void hashBcryptVersao2yCusto8Com60Caracteres() {
        String hash = Senha.gerarHash("13572468".toCharArray());
        assertEquals(60, hash.length());
        assertTrue(hash, hash.matches("\\$2y\\$08\\$[./A-Za-z0-9]{53}"));
    }

    @Test
    public void saltAleatorioGeraHashesDiferentesParaAMesmaSenha() {
        assertNotEquals(Senha.gerarHash("13572468".toCharArray()), Senha.gerarHash("13572468".toCharArray()));
    }

    @Test
    public void verificaOExemploDoEnunciado() {
        String exemplo = "$2y$08$ajDZdV0XFoYiLRE0ZrSx6OmRbhhB5qM.Ap6c.0LqRu2cIY1jpytuO";
        assertTrue(Senha.verificar(exemplo, "13572468".toCharArray()));
        assertFalse(Senha.verificar(exemplo, "13572469".toCharArray()));
    }

    @Test
    public void verificarComHashInvalidoRetornaFalso() {
        assertFalse(Senha.verificar("nao-eh-bcrypt", "13572468".toCharArray()));
    }

    @Test
    public void descobreASenhaAPartirDosParesPressionados() {
        String hash = Senha.gerarHash("24681357".toCharArray());
        for (int i = 0; i < 3; i++) {
            char[] senha = Senha.descobrir(hash, Cenario.digitar("24681357"));
            assertArrayEquals("24681357".toCharArray(), senha);
        }
    }

    @Test
    public void descobreSenhasDeNoveEDezDigitos() {
        String hash9 = Senha.gerarHash("135724680".toCharArray());
        String hash10 = Senha.gerarHash("9753186420".toCharArray());
        assertArrayEquals("135724680".toCharArray(), Senha.descobrir(hash9, Cenario.digitar("135724680")));
        assertArrayEquals("9753186420".toCharArray(), Senha.descobrir(hash10, Cenario.digitar("9753186420")));
    }

    @Test
    public void senhaErradaNaoEhEncontrada() {
        String hash = Senha.gerarHash("24681357".toCharArray());
        // ultimo botao pressionado nao contem o digito 7
        assertNull(Senha.descobrir(hash, pares("24", "40", "68", "82", "19", "36", "58", "90")));
        // nenhum botao contem o digito correto
        assertNull(Senha.descobrir(hash, pares("13", "57", "02", "49", "78", "29", "46", "08")));
    }

    @Test
    public void botaoComODigitoCorretoEmQualquerPosicaoDoParEhAceito() {
        // o botao nao distingue os seus dois digitos
        String hash = Senha.gerarHash("24681357".toCharArray());
        assertArrayEquals("24681357".toCharArray(),
                          Senha.descobrir(hash, pares("24", "40", "68", "82", "19", "36", "58", "79")));
        assertArrayEquals("24681357".toCharArray(),
                          Senha.descobrir(hash, pares("02", "34", "56", "78", "91", "23", "45", "67")));
    }

    @Test
    public void quantidadeDeParesForaDe8a10NaoEhAceita() {
        String hash = Senha.gerarHash("24681357".toCharArray());
        assertNull(Senha.descobrir(hash, Cenario.digitar("2468135")));
        assertNull(Senha.descobrir(hash, new ArrayList<char[]>()));
        List<char[]> onze = Cenario.digitar("2468135790");
        onze.add(new char[] {'1', '2'});
        assertNull(Senha.descobrir(hash, onze));
    }

    @Test
    public void senhaCorretaComPrefixoValidoNaoBastaQuandoFaltamDigitos() {
        String hash = Senha.gerarHash("246813579".toCharArray());
        assertNull(Senha.descobrir(hash, Cenario.digitar("24681357")));
    }

    @Test
    public void cincoBotoesComDoisNumerosSemRepeticao() {
        TecladoVirtual t = new TecladoVirtual();
        for (int rodada = 0; rodada < 200; rodada++) {
            Set<Character> digitos = new HashSet<Character>();
            for (int b = 0; b < TecladoVirtual.BOTOES; b++) {
                char[] botao = t.getBotao(b);
                assertEquals(2, botao.length);
                digitos.add(botao[0]);
                digitos.add(botao[1]);
            }
            assertEquals(new HashSet<Character>(Arrays.asList('0', '1', '2', '3', '4', '5', '6', '7', '8', '9')),
                         digitos);
            t.embaralhar();
        }
    }

    @Test
    public void cadaPressionamentoRegistraOParERedistribuiOsNumeros() {
        TecladoVirtual t = new TecladoVirtual(new Random(1416));
        int mudancas = 0;
        for (int i = 0; i < 10; i++) {
            String antes = rotulos(t);
            char[] botao = t.getBotao(i % TecladoVirtual.BOTOES);
            assertTrue(t.pressionar(i % TecladoVirtual.BOTOES));
            assertArrayEquals(botao, t.getPressionados().get(i));
            if (!antes.equals(rotulos(t))) {
                mudancas++;
            }
        }
        assertTrue("a distribuicao deve mudar a cada pressionamento", mudancas >= 9);
    }

    @Test
    public void distribuicaoEhAleatoria() {
        TecladoVirtual t = new TecladoVirtual();
        Map<String, Integer> posicoes = new HashMap<String, Integer>();
        for (int i = 0; i < 2000; i++) {
            for (int b = 0; b < TecladoVirtual.BOTOES; b++) {
                for (char d : t.getBotao(b)) {
                    String chave = d + "@" + b;
                    Integer n = posicoes.get(chave);
                    posicoes.put(chave, n == null ? 1 : n + 1);
                }
            }
            t.embaralhar();
        }
        // todo digito aparece em todos os botoes
        assertEquals(50, posicoes.size());
    }

    @Test
    public void limiteDeDezPressionamentosApagarELimpar() {
        TecladoVirtual t = new TecladoVirtual();
        for (int i = 0; i < 10; i++) {
            assertTrue(t.pressionar(0));
        }
        assertFalse(t.pressionar(0));
        assertEquals(10, t.getQuantidade());
        t.apagarUltimo();
        assertEquals(9, t.getQuantidade());
        t.limpar();
        assertEquals(0, t.getQuantidade());
    }

    private static List<char[]> pares(String... botoes) {
        List<char[]> lista = new ArrayList<char[]>();
        for (String b : botoes) {
            lista.add(b.toCharArray());
        }
        return lista;
    }

    private static String rotulos(TecladoVirtual t) {
        StringBuilder s = new StringBuilder();
        for (int b = 0; b < TecladoVirtual.BOTOES; b++) {
            s.append(t.getRotulo(b)).append('|');
        }
        return s.toString();
    }
}
