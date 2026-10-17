import java.security.SecureRandom;
import java.util.*;
import java.util.stream.IntStream;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

//
// Senha pessoal: regras de formacao, armazenamento bcrypt e verificacao a partir
// do teclado virtual numerico sobrecarregado
public final class Senha {

    public static final String VERSAO_BCRYPT = "2y";
    public static final int    CUSTO_BCRYPT  = 8;
    public static final int    TAMANHO_MIN   = 8;
    public static final int    TAMANHO_MAX   = 10;

    private Senha() {
    }

    //
    // senhas pessoais sao formadas por oito, nove ou dez digitos de 0 a 9 e nao
    // podem ter sequencias de numeros repetidos (o mesmo digito em seguida)
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

    //
    // Valor_Armazenado = $2y$08$BASE64(salt)BASE64(hash) (60 caracteres)
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

    //
    // Cada botao pressionado no teclado sobrecarregado fornece um par de digitos.
    // Testa as combinacoes possiveis (uma escolha por par) contra o hash bcrypt e
    // retorna a senha encontrada, ou null se nenhuma combinacao for a senha.
    public static char[] descobrir(final String hashArmazenado, List<char[]> pares) {
        final int n = pares.size();
        if (n < TAMANHO_MIN || n > TAMANHO_MAX) {
            return null;
        }
        final char[][] p = pares.toArray(new char[n][]);
        OptionalInt encontrada = IntStream.range(0, 1 << n).parallel().filter(mascara -> {
            char[] candidata = candidata(p, mascara);
            try {
                // senhas validas nunca tem digitos repetidos em sequencia
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
