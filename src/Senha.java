// Gabriel de Barros Arruda - 2311723
// Erica Oliveira Regnier - 2211893

import java.security.SecureRandom;
import java.util.*;
import java.util.stream.IntStream;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

public final class Senha {

    public static final String VERSAO_BCRYPT = "2y";
    public static final int    CUSTO_BCRYPT  = 8;
    public static final int    TAMANHO_MIN   = 8;
    public static final int    TAMANHO_MAX   = 10;

    private Senha() {
    }

    public static boolean formatoValido(char[] senha) {
        if (senha == null || senha.length < TAMANHO_MIN || senha.length > TAMANHO_MAX) {
            return false;
        }
        for (int i = 0; i < senha.length; i++) {
            if (senha[i] < '0' || senha[i] > '9') {
                return false;
            }
            if (i > 0 && senha[i] == senha[i - 1]) {
                return false;
            }
        }
        return true;
    }

    public static String gerarHash(char[] senha) {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return OpenBSDBCrypt.generate(VERSAO_BCRYPT, senha, salt, CUSTO_BCRYPT);
    }

    public static boolean verificar(String hashArmazenado, char[] senha) {
        try {
            return OpenBSDBCrypt.checkPassword(hashArmazenado, senha);
        } catch (RuntimeException e) {
            return false;
        }
    }

    public static char[] descobrir(final String hashArmazenado, List<char[]> pares) {
        final int n = pares.size();
        if (n < TAMANHO_MIN || n > TAMANHO_MAX) {
            return null;
        }
        final char[][] p = pares.toArray(new char[n][]);
        OptionalInt encontrada = IntStream.range(0, 1 << n).parallel().filter(mascara -> {
            char[] candidata = candidata(p, mascara);
            try {
                // senha nao repete digito em sequencia
                return formatoValido(candidata) && verificar(hashArmazenado, candidata);
            } finally {
                Arrays.fill(candidata, '\0');
            }
        }).findAny();
        return encontrada.isPresent() ? candidata(p, encontrada.getAsInt()) : null;
    }

    private static char[] candidata(char[][] pares, int mascara) {
        char[] c = new char[pares.length];
        for (int i = 0; i < pares.length; i++) {
            c[i] = pares[i][(mascara >> i) & 1];
        }
        return c;
    }
}
