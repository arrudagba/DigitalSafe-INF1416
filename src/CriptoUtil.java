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

//
// Rotinas criptograficas do Cofre Digital (JCA)
public final class CriptoUtil {

    public static final String CIFRA_SIMETRICA  = "AES/ECB/PKCS5Padding";
    public static final String CIFRA_ENVELOPE   = "RSA/ECB/PKCS1Padding";
    public static final String PRNG             = "SHA1PRNG";
    public static final int    TAMANHO_CHAVE_AES = 256;

    // tamanhos do array aleatorio usado para validar a chave privada
    public static final int TESTE_CADASTRO = 10240;
    public static final int TESTE_LOGVIEW  = 2048;

    // algoritmos aceitos na verificacao das assinaturas dos arquivos da pasta segura
    private static final String[] ASSINATURAS_RSA = {"SHA1withRSA", "SHA256withRSA", "SHA512withRSA", "MD5withRSA"};

    private static final String OID_EMAIL = "1.2.840.113549.1.9.1";

    // resultado da validacao de uma chave privada
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

    // =====================================================================
    // Chave simetrica AES gerada com SHA1PRNG a partir de uma semente
    // =====================================================================

    public static SecretKey chaveAES(byte[] semente) throws GeneralSecurityException {
        SecureRandom prng = SecureRandom.getInstance(PRNG);
        prng.setSeed(semente);
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(TAMANHO_CHAVE_AES, prng);
        return keyGen.generateKey();
    }

    //
    // chave AES gerada a partir de uma frase secreta ou senha pessoal
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

    // =====================================================================
    // Certificado digital X.509
    // =====================================================================

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

    //
    // representacao PEM (Privacy-Enhanced Mail) do certificado
    public static String paraPem(X509Certificate certificado) throws CertificateEncodingException {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                              .encodeToString(certificado.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----\n";
    }

    //
    // nome distinto (DN) legivel, com o e-mail como EMAILADDRESS em vez do OID
    public static String nomeLegivel(X500Principal principal) {
        Map<String, String> oids = new HashMap<String, String>();
        oids.put(OID_EMAIL, "EMAILADDRESS");
        return principal.getName(X500Principal.RFC2253, oids);
    }

    //
    // valor de um atributo (CN, EMAILADDRESS, ...) do campo Sujeito ou Emissor
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

    //
    // login name do usuario: e-mail presente no campo Sujeito do certificado
    public static String extrairEmail(X509Certificate certificado) {
        String email = atributo(certificado.getSubjectX500Principal(), "EMAILADDRESS");
        if (email == null) {
            email = atributo(certificado.getSubjectX500Principal(), "E");
        }
        return email;
    }

    //
    // nome do usuario (Friendly Name): CN do campo Sujeito do certificado
    public static String extrairNome(X509Certificate certificado) {
        return atributo(certificado.getSubjectX500Principal(), "CN");
    }

    public static boolean emailValido(String email) {
        return email != null && email.matches("[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,}");
    }

    // =====================================================================
    // Chave privada (PKCS8 em BASE64, criptografada com AES/ECB/PKCS5Padding)
    // =====================================================================

    //
    // decripta o arquivo binario da chave privada com a chave AES gerada a partir
    // da frase secreta e restaura a PrivateKey; lanca GeneralSecurityException se a
    // frase secreta for invalida
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

    //
    // o conteudo decriptado eh a chave PKCS8 codificada em BASE64 (com ou sem as
    // linhas -----BEGIN/END PRIVATE KEY-----); aceita tambem o DER binario
    private static byte[] decodificarPkcs8(byte[] decifrado) throws InvalidKeyException {
        String texto = new String(decifrado, StandardCharsets.ISO_8859_1);
        StringBuilder base64 = new StringBuilder();
        for (String linha : texto.split("\r?\n")) {
            if (!linha.startsWith("-----")) {
                base64.append(linha.trim());
            }
        }
        try {
            // decodificador estrito: lanca excecao se houver caractere fora do BASE64
            byte[] der = Base64.getDecoder().decode(base64.toString());
            if (der.length > 0) {
                return der;
            }
        } catch (IllegalArgumentException e) {
            // nao eh BASE64: considera o DER binario
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

    //
    // assina um array aleatorio com a chave privada e verifica a assinatura com
    // a chave publica do certificado
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

    //
    // testa a frase secreta e verifica a chave privada com a assinatura digital de
    // um array aleatorio de "tamanho" bytes e a chave publica do certificado
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

    //
    // le o arquivo da chave privada; retorna null se o caminho for invalido
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

    // =====================================================================
    // Envelope digital e assinatura digital dos arquivos da pasta segura
    // =====================================================================

    //
    // abre o envelope digital (.env ou .shr) com a chave privada do destinatario,
    // obtendo a semente SHA1PRNG que gera a chave secreta AES
    public static byte[] abrirEnvelope(byte[] envelope, PrivateKey privada) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIFRA_ENVELOPE);
        cipher.init(Cipher.DECRYPT_MODE, privada);
        return cipher.doFinal(envelope);
    }

    //
    // decripta um arquivo .enc a partir do seu envelope digital
    public static byte[] decifrarComEnvelope(byte[] cifrado, byte[] envelope, PrivateKey privada)
            throws GeneralSecurityException {
        byte[] semente = abrirEnvelope(envelope, privada);
        try {
            return decifrarAES(chaveAES(semente), cifrado);
        } finally {
            Arrays.fill(semente, (byte) 0);
        }
    }

    //
    // verifica a integridade e a autenticidade dos dados com a assinatura digital
    // binaria (.asd) e a chave publica de quem assinou
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

    // =====================================================================
    // Auxiliares
    // =====================================================================

    //
    // converte char[] em bytes UTF-8 sem criar String (permite apagar da memoria)
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
