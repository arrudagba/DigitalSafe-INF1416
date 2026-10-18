// Gabriel de Barros Arruda - 2311723
// Erica Oliveira Regnier - 2211893

import static org.junit.Assert.*;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import org.junit.*;

public class TOTPBase32Test {

    // "12345678901234567890" (RFC 6238)
    private static final String SEGREDO_RFC = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    private final Base32 base32 = new Base32(Base32.Alphabet.BASE32, false, false);

    @Test
    public void base32VetoresDoRfc4648() {
        String[][] vetores = {{"", ""}, {"f", "MY"}, {"fo", "MZXQ"}, {"foo", "MZXW6"}, {"foob", "MZXW6YQ"},
                              {"fooba", "MZXW6YTB"}, {"foobar", "MZXW6YTBOI"}};
        for (String[] v : vetores) {
            byte[] dados = v[0].getBytes(StandardCharsets.US_ASCII);
            assertEquals(v[0], v[1], base32.toString(dados));
            assertArrayEquals(v[0], dados, base32.fromString(v[1]));
        }
    }

    @Test
    public void base32AceitaMinusculasEEspacos() {
        assertArrayEquals("foobar".getBytes(StandardCharsets.US_ASCII), base32.fromString("mzxw 6ytb oi"));
    }

    @Test
    public void base32RejeitaCaracteresForaDoAlfabeto() {
        assertNull(base32.fromString("MZXW1YTB"));
        assertNull(base32.fromString("MZXW8YTB"));
    }

    @Test
    public void segredoDe160BitsTem32CaracteresBase32() {
        byte[] segredo = new byte[20];
        new java.security.SecureRandom().nextBytes(segredo);
        String codificado = base32.toString(segredo);
        assertEquals(32, codificado.length());
        assertArrayEquals(segredo, base32.fromString(codificado));
    }

    @Test
    public void vetoresDoRfc6238ComSeisAlgarismos() throws Exception {
        TOTP totp = new TOTP(SEGREDO_RFC, 30);
        // RFC 6238 (SHA1), ultimos 6 digitos
        long[] tempos = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
        String[] codigos = {"287082", "081804", "050471", "005924", "279037", "353130"};
        for (int i = 0; i < tempos.length; i++) {
            assertEquals("T = " + tempos[i], codigos[i], codigo(totp, tempos[i] / 30));
        }
    }

    @Test
    public void codigoTemSeisAlgarismosComZerosAEsquerda() throws Exception {
        TOTP totp = new TOTP(SEGREDO_RFC, 30);
        assertEquals("005924", codigo(totp, 1234567890L / 30));
        assertTrue(totp.generateCode().matches("[0-9]{6}"));
    }

    @Test
    public void generateCodeUsaOIntervaloAtualDe30Segundos() throws Exception {
        TOTP totp = new TOTP(SEGREDO_RFC, 30);
        long intervalo = intervaloSeguro();
        assertEquals(codigo(totp, intervalo), totp.generateCode());
    }

    @Test
    public void validaComMargemDe30SegundosParaMenosEParaMais() throws Exception {
        TOTP totp = new TOTP(SEGREDO_RFC, 30);
        long intervalo = intervaloSeguro();
        assertTrue("atual", totp.validateCode(codigo(totp, intervalo)));
        assertTrue("30 s a menos", totp.validateCode(codigo(totp, intervalo - 1)));
        assertTrue("30 s a mais", totp.validateCode(codigo(totp, intervalo + 1)));
    }

    @Test
    public void rejeitaCodigoForaDaMargem() throws Exception {
        TOTP totp = new TOTP(SEGREDO_RFC, 30);
        long intervalo = intervaloSeguro();
        String atual = codigo(totp, intervalo), menos = codigo(totp, intervalo - 1), mais = codigo(totp, intervalo + 1);
        for (long d : new long[] {-3, -2, 2, 3}) {
            String c = codigo(totp, intervalo + d);
            Assume.assumeFalse(c.equals(atual) || c.equals(menos) || c.equals(mais));
            assertFalse("intervalo " + d, totp.validateCode(c));
        }
    }

    @Test
    public void rejeitaEntradasMalFormadas() throws Exception {
        TOTP totp = new TOTP(SEGREDO_RFC, 30);
        for (String entrada : new String[] {null, "", "12345", "1234567", "abcdef", "12 456"}) {
            assertFalse(String.valueOf(entrada), totp.validateCode(entrada));
        }
    }

    @Test
    public void codigoDependeDaChaveSecreta() throws Exception {
        TOTP a = new TOTP(SEGREDO_RFC, 30);
        TOTP b = new TOTP("JXXMGK33L7S3H3JOY5GMUXC7G7ASJHTD", 30);
        int iguais = 0;
        for (long t = 0; t < 20; t++) {
            if (codigo(a, t).equals(codigo(b, t))) {
                iguais++;
            }
        }
        assertTrue(iguais < 3);
    }

    @Test(expected = Exception.class)
    public void construtorRejeitaBase32Invalido() throws Exception {
        new TOTP("CHAVE-INVALIDA-1890", 30);
    }

    @Test(expected = Exception.class)
    public void construtorRejeitaChaveNula() throws Exception {
        new TOTP(null, 30);
    }

    @Test(expected = Exception.class)
    public void construtorRejeitaIntervaloInvalido() throws Exception {
        new TOTP(SEGREDO_RFC, 0);
    }

    static String codigo(TOTP totp, long intervalo) throws Exception {
        Method m = TOTP.class.getDeclaredMethod("TOTPCode", long.class);
        m.setAccessible(true);
        return (String) m.invoke(totp, intervalo);
    }

    static long intervaloSeguro() throws InterruptedException {
        long segundos = System.currentTimeMillis() / 1000;
        if (segundos % 30 >= 28) {
            Thread.sleep(3000);
            segundos = System.currentTimeMillis() / 1000;
        }
        return segundos / 30;
    }
}
