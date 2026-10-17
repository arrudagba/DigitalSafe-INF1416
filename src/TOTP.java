import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Date;

//
// Time-based One Time Password (RFC 6238) com HMAC-SHA1 (RFC 4226) e chave
// secreta codificada em BASE32 (RFC 4648). Implementada usando apenas as classes
// de apoio Mac, SecretKeySpec, Date e Base32, conforme a estrutura do enunciado.
public class TOTP {
    private byte [] key = null;
    private long timeStepInSeconds = 30;

    // Construtor da classe. Recebe a chave secreta em BASE32 e o intervalo
    // de tempo a ser adotado (default = 30 segundos). Deve decodificar a
    // chave secreta e armazenar em key. Em caso de erro, gera Exception.
    public TOTP(String base32EncodedSecret, long timeStepInSeconds)
    throws Exception {
        if (base32EncodedSecret == null) {
            throw new Exception("Chave secreta TOTP ausente.");
        }
        if (timeStepInSeconds <= 0) {
            throw new Exception("Intervalo de tempo TOTP invalido: " + timeStepInSeconds);
        }
        Base32 base32 = new Base32(Base32.Alphabet.BASE32, false, false);
        byte[] decodificada = base32.fromString(base32EncodedSecret);
        if (decodificada == null || decodificada.length == 0) {
            throw new Exception("Chave secreta TOTP com codificacao BASE32 invalida.");
        }
        this.key = decodificada;
        this.timeStepInSeconds = timeStepInSeconds;
    }

    // Recebe o HASH HMAC-SHA1 e determina o código TOTP de 6 algarismos
    // decimais, prefixado com zeros quando necessário.
    private String getTOTPCodeFromHash(byte[] hash) {
        // truncamento dinamico (RFC 4226, secao 5.3): os 4 bits menos
        // significativos do ultimo byte indicam o deslocamento
        int offset = hash[hash.length - 1] & 0x0F;
        int binario = ((hash[offset]     & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    |  (hash[offset + 3] & 0xFF);
        String codigo = Integer.toString(binario % 1000000);
        while (codigo.length() < 6) {
            codigo = "0" + codigo;
        }
        return codigo;
    }

    // Recebe o contador e a chave secreta para produzir o hash HMAC-SHA1.
    private byte[] HMAC_SHA1(byte[] counter, byte[] keyByteArray) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(keyByteArray, "HmacSHA1"));
            return mac.doFinal(counter);
        } catch (Exception e) {
            throw new IllegalStateException("Falha no calculo do HMAC-SHA1: " + e.getMessage(), e);
        }
    }

    // Recebe o intervalo de tempo e executa o algoritmo TOTP para produzir
    // o código TOTP. Usa os métodos auxiliares getTOTPCodeFromHash e HMAC_SHA1.
    private String TOTPCode(long timeInterval) {
        // contador de 8 bytes em big-endian (RFC 4226)
        byte[] counter = new byte[8];
        long valor = timeInterval;
        for (int i = counter.length - 1; i >= 0; i--) {
            counter[i] = (byte) (valor & 0xFF);
            valor >>>= 8;
        }
        return getTOTPCodeFromHash(HMAC_SHA1(counter, key));
    }

    // Método que é utilizado para solicitar a geração do código TOTP.
    public String generateCode() {
        long intervalo = (new Date().getTime() / 1000) / timeStepInSeconds;
        return TOTPCode(intervalo);
    }

    // Método que é utilizado para validar um código TOTP (inputTOTP).
    // Deve considerar um atraso ou adiantamento de 30 segundos no
    // relógio da máquina que gerou o código TOTP.
    public boolean validateCode(String inputTOTP) {
        if (inputTOTP == null) {
            return false;
        }
        String codigo = inputTOTP.trim();
        if (!codigo.matches("[0-9]{6}")) {
            return false;
        }
        // (i) intervalo atual, (ii) um intervalo a menos e (iii) um intervalo a mais
        long intervalo = (new Date().getTime() / 1000) / timeStepInSeconds;
        return codigo.equals(TOTPCode(intervalo))
            || codigo.equals(TOTPCode(intervalo - 1))
            || codigo.equals(TOTPCode(intervalo + 1));
    }
}
