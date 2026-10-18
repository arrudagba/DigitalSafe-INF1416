// Gabriel de Barros Arruda - 2311723
// Erica Oliveira Regnier - 2211893

import java.security.SecureRandom;
import java.util.*;

public class TecladoVirtual {

    public static final int BOTOES = 5;

    private final Random random;
    private final char[][] botoes = new char[BOTOES][2];
    private final List<char[]> pressionados = new ArrayList<char[]>();

    public TecladoVirtual() {
        this(new SecureRandom());
    }

    TecladoVirtual(Random random) {
        this.random = random;
        embaralhar();
    }

    public final void embaralhar() {
        char[] digitos = "0123456789".toCharArray();
        for (int i = digitos.length - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            char t = digitos[i];
            digitos[i] = digitos[j];
            digitos[j] = t;
        }
        for (int b = 0; b < BOTOES; b++) {
            botoes[b][0] = digitos[2 * b];
            botoes[b][1] = digitos[2 * b + 1];
        }
        Arrays.fill(digitos, '\0');
    }

    public char[] getBotao(int indice) {
        return botoes[indice].clone();
    }

    public String getRotulo(int indice) {
        return botoes[indice][0] + " ou " + botoes[indice][1];
    }

    public boolean pressionar(int indice) {
        if (pressionados.size() >= Senha.TAMANHO_MAX) {
            return false;
        }
        pressionados.add(botoes[indice].clone());
        embaralhar();
        return true;
    }

    public void apagarUltimo() {
        if (!pressionados.isEmpty()) {
            Arrays.fill(pressionados.remove(pressionados.size() - 1), '\0');
        }
        embaralhar();
    }

    public int getQuantidade() {
        return pressionados.size();
    }

    public List<char[]> getPressionados() {
        return Collections.unmodifiableList(pressionados);
    }

    public void limpar() {
        for (char[] par : pressionados) {
            Arrays.fill(par, '\0');
        }
        pressionados.clear();
        embaralhar();
    }
}
