// Gabriel de Barros Arruda - 2311723
// Erica Oliveira Regnier - 2211893

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import javax.crypto.*;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

public final class CriptoUtil {

    public static final String CIFRA_SIMETRICA  = "AES/ECB/PKCS5Padding";
    public static final String CIFRA_ENVELOPE   = "RSA/ECB/PKCS1Padding";
    public static final String PRNG             = "SHA1PRNG";
    public static final int    TAMANHO_CHAVE_AES = 256;

    // tamanhos do array de teste da chave privada
    public static final int TESTE_CADASTRO = 10240;
    public static final int TESTE_LOGVIEW  = 2048;

    // algoritmos aceitos nos arquivos .asd
    private static final String[] ASSINATURAS_RSA = {"SHA1withRSA", "SHA256withRSA", "SHA512withRSA", "MD5withRSA"};

    private static final String OID_EMAIL = "1.2.840.113549.1.9.1";

    public enum StatusChave { OK, CAMINHO_INVALIDO, FRASE_INVALIDA, ASSINATURA_INVALIDA }

    public static final class ResultadoChave {
        public final StatusChave status;
        public final PrivateKey chave;

        ResultadoChave(StatusChave status, PrivateKey chave) {
            this.status = status;
            this.chave = chave;
        }
    }

    private CriptoUtil() {
    }

    public static SecretKey chaveAES(byte[] semente) throws GeneralSecurityException {
        SecureRandom prng = SecureRandom.getInstance(PRNG);
        prng.setSeed(semente);
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(TAMANHO_CHAVE_AES, prng);
        return keyGen.generateKey();
    }

    public static SecretKey chaveAES(char[] frase) throws GeneralSecurityException {
        byte[] semente = paraBytes(frase);
        try {
            return chaveAES(semente);
        } finally {
            Arrays.fill(semente, (byte) 0);
        }
    }

    public static byte[] cifrarAES(SecretKey chave, byte[] dados) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIFRA_SIMETRICA);
        cipher.init(Cipher.ENCRYPT_MODE, chave);
        return cipher.doFinal(dados);
    }

    public static byte[] decifrarAES(SecretKey chave, byte[] dados) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIFRA_SIMETRICA);
        cipher.init(Cipher.DECRYPT_MODE, chave);
        return cipher.doFinal(dados);
    }

    public static X509Certificate carregarCertificado(byte[] dados) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(dados));
    }

    public static X509Certificate carregarCertificado(File arquivo) throws IOException, CertificateException {
        return carregarCertificado(Files.readAllBytes(arquivo.toPath()));
    }

    public static X509Certificate certificadoDePem(String pem) throws CertificateException {
        return carregarCertificado(pem.getBytes(StandardCharsets.US_ASCII));
    }

    public static String paraPem(X509Certificate certificado) throws CertificateEncodingException {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                              .encodeToString(certificado.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----\n";
    }

    public static String nomeLegivel(X500Principal principal) {
        Map<String, String> oids = new HashMap<String, String>();
        oids.put(OID_EMAIL, "EMAILADDRESS");
        return principal.getName(X500Principal.RFC2253, oids);
    }

    public static String atributo(X500Principal principal, String nome) {
        try {
            LdapName dn = new LdapName(nomeLegivel(principal));
            for (Rdn rdn : dn.getRdns()) {
                if (rdn.getType().equalsIgnoreCase(nome)) {
                    return rdn.getValue().toString().trim();
                }
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    public static String extrairEmail(X509Certificate certificado) {
        String email = atributo(certificado.getSubjectX500Principal(), "EMAILADDRESS");
        if (email == null) {
            email = atributo(certificado.getSubjectX500Principal(), "E");
        }
        return email;
    }

    public static String extrairNome(X509Certificate certificado) {
        return atributo(certificado.getSubjectX500Principal(), "CN");
    }

    public static boolean emailValido(String email) {
        return email != null && email.matches("[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,}");
    }

    public static PrivateKey decifrarChavePrivada(byte[] arquivoCifrado, char[] frase)
            throws GeneralSecurityException {
        byte[] decifrado = decifrarAES(chaveAES(frase), arquivoCifrado);
        byte[] pkcs8 = null;
        try {
            pkcs8 = decodificarPkcs8(decifrado);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8);
            for (String algoritmo : new String[] {"RSA", "EC", "DSA"}) {
                try {
                    return KeyFactory.getInstance(algoritmo).generatePrivate(spec);
                } catch (GeneralSecurityException e) {
                    // tenta o proximo algoritmo
                }
            }
            throw new InvalidKeyException("Conteudo decriptado nao eh uma chave privada PKCS8.");
        } finally {
            Arrays.fill(decifrado, (byte) 0);
            if (pkcs8 != null) {
                Arrays.fill(pkcs8, (byte) 0);
            }
        }
    }

    private static byte[] decodificarPkcs8(byte[] decifrado) throws InvalidKeyException {
        String texto = new String(decifrado, StandardCharsets.ISO_8859_1);
        StringBuilder base64 = new StringBuilder();
        for (String linha : texto.split("\r?\n")) {
            if (!linha.startsWith("-----")) {
                base64.append(linha.trim());
            }
        }
        try {
            // decodificador estrito
            byte[] der = Base64.getDecoder().decode(base64.toString());
            if (der.length > 0) {
                return der;
            }
        } catch (IllegalArgumentException e) {
            // DER binario
        }
        if (decifrado.length > 0 && decifrado[0] == 0x30) {
            return decifrado.clone();
        }
        throw new InvalidKeyException("Formato da chave privada desconhecido.");
    }

    public static String algoritmoAssinatura(Key chave) {
        String algoritmo = chave.getAlgorithm();
        if (algoritmo.equals("EC")) {
            return "SHA256withECDSA";
        }
        if (algoritmo.equals("DSA")) {
            return "SHA256withDSA";
        }
        return "SHA256withRSA";
    }

    public static boolean verificarParDeChaves(PrivateKey privada, PublicKey publica, int tamanho) {
        try {
            byte[] aleatorio = new byte[tamanho];
            new SecureRandom().nextBytes(aleatorio);
            Signature assinador = Signature.getInstance(algoritmoAssinatura(privada));
            assinador.initSign(privada);
            assinador.update(aleatorio);
            byte[] assinatura = assinador.sign();

            Signature verificador = Signature.getInstance(algoritmoAssinatura(privada));
            verificador.initVerify(publica);
            verificador.update(aleatorio);
            return verificador.verify(assinatura);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public static ResultadoChave validarChavePrivada(byte[] arquivoCifrado, char[] frase,
                                                     X509Certificate certificado, int tamanho) {
        if (arquivoCifrado == null) {
            return new ResultadoChave(StatusChave.CAMINHO_INVALIDO, null);
        }
        PrivateKey privada;
        try {
            privada = decifrarChavePrivada(arquivoCifrado, frase);
        } catch (GeneralSecurityException e) {
            return new ResultadoChave(StatusChave.FRASE_INVALIDA, null);
        }
        if (!verificarParDeChaves(privada, certificado.getPublicKey(), tamanho)) {
            return new ResultadoChave(StatusChave.ASSINATURA_INVALIDA, null);
        }
        return new ResultadoChave(StatusChave.OK, privada);
    }

    public static byte[] lerArquivo(String caminho) {
        if (caminho == null || caminho.trim().isEmpty()) {
            return null;
        }
        File arquivo = new File(caminho.trim());
        if (!arquivo.isFile() || !arquivo.canRead()) {
            return null;
        }
        try {
            return Files.readAllBytes(arquivo.toPath());
        } catch (IOException e) {
            return null;
        }
    }

    public static byte[] abrirEnvelope(byte[] envelope, PrivateKey privada) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIFRA_ENVELOPE);
        cipher.init(Cipher.DECRYPT_MODE, privada);
        return cipher.doFinal(envelope);
    }

    public static byte[] decifrarComEnvelope(byte[] cifrado, byte[] envelope, PrivateKey privada)
            throws GeneralSecurityException {
        byte[] semente = abrirEnvelope(envelope, privada);
        try {
            return decifrarAES(chaveAES(semente), cifrado);
        } finally {
            Arrays.fill(semente, (byte) 0);
        }
    }

    public static boolean verificarAssinatura(byte[] dados, byte[] assinatura, PublicKey publica) {
        String[] algoritmos = publica.getAlgorithm().equals("RSA")
                            ? ASSINATURAS_RSA
                            : new String[] {algoritmoAssinatura(publica)};
        for (String algoritmo : algoritmos) {
            try {
                Signature verificador = Signature.getInstance(algoritmo);
                verificador.initVerify(publica);
                verificador.update(dados);
                if (verificador.verify(assinatura)) {
                    return true;
                }
            } catch (GeneralSecurityException e) {
                // tenta o proximo algoritmo
            }
        }
        return false;
    }

    public static byte[] paraBytes(char[] texto) {
        java.nio.ByteBuffer buffer = StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(texto));
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes);
        if (buffer.hasArray()) {
            Arrays.fill(buffer.array(), (byte) 0);
        }
        return bytes;
    }

    public static String serialHex(BigInteger serial) {
        return serial.toString(16).toUpperCase();
    }
}
