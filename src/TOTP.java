// Gabriel de Barros Arruda - 2311723
// Erica Oliveira Regnier - 2211893

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Date;

public class TOTP {
    private byte [] key = null;
    private long timeStepInSeconds = 30;

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

    private String getTOTPCodeFromHash(byte[] hash) {
        // truncamento dinamico (RFC 4226)
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

    private byte[] HMAC_SHA1(byte[] counter, byte[] keyByteArray) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(keyByteArray, "HmacSHA1"));
            return mac.doFinal(counter);
        } catch (Exception e) {
            throw new IllegalStateException("Falha no calculo do HMAC-SHA1: " + e.getMessage(), e);
        }
    }

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

    public String generateCode() {
        long intervalo = (new Date().getTime() / 1000) / timeStepInSeconds;
        return TOTPCode(intervalo);
    }

    public boolean validateCode(String inputTOTP) {
        if (inputTOTP == null) {
            return false;
        }
        String codigo = inputTOTP.trim();
        if (!codigo.matches("[0-9]{6}")) {
            return false;
        }
        // intervalo atual, anterior e seguinte
        long intervalo = (new Date().getTime() / 1000) / timeStepInSeconds;
        return codigo.equals(TOTPCode(intervalo))
            || codigo.equals(TOTPCode(intervalo - 1))
            || codigo.equals(TOTPCode(intervalo + 1));
    }
}
