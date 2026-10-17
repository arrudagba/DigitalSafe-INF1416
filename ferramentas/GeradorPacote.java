import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.crypto.Cipher;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

//
// Ferramenta de apoio (nao faz parte do Cofre Digital): gera o material de teste
// no mesmo formato descrito no enunciado.
//
//   Keys/  - certificados X.509 (PEM) e chaves privadas PKCS8 em BASE64 cifradas
//            com AES/ECB/PKCS5Padding (chave de 256 bits gerada com SHA1PRNG a
//            partir da frase secreta)
//   Files/ - pasta segura: index e share (protegidos com as chaves do
//            administrador) e arquivos secretos (.enc, .env, .asd e .shr)
public class GeradorPacote {

    public static final String ADMIN  = "admin@inf1416.puc-rio.br";
    public static final String USER01 = "user01@inf1416.puc-rio.br";
    public static final String USER02 = "user02@inf1416.puc-rio.br";

    public static final String FRASE_ADMIN  = "admin";
    public static final String FRASE_USER01 = "user01";
    public static final String FRASE_USER02 = "user02";

    public static final String ASSINATURA = "SHA256withRSA";

    //
    // usuario do pacote de teste
    public static class Identidade {
        public final String prefixo, nome, email, frase;
        public KeyPair par;
        public X509Certificate certificado;
        public File arquivoCertificado, arquivoChave;

        Identidade(String prefixo, String nome, String email, String frase) {
            this.prefixo = prefixo;
            this.nome = nome;
            this.email = email;
            this.frase = frase;
        }
    }

    public static class Pacote {
        public File raiz, keys, files;
        public Identidade ca, admin, user01, user02;
    }

    public static void main(String[] args) throws Exception {
        File destino = new File(args.length > 0 ? args[0] : "pacote");
        Pacote p = gerar(destino);
        System.out.println("Pacote de teste gerado em " + p.raiz.getAbsolutePath());
        for (Identidade id : new Identidade[] {p.admin, p.user01, p.user02}) {
            System.out.println("  " + id.email + ": " + id.arquivoCertificado.getPath() + " | "
                             + id.arquivoChave.getPath() + " | frase secreta: " + id.frase);
        }
        System.out.println("  pasta segura: " + p.files.getPath());
    }

    public static Pacote gerar(File destino) throws Exception {
        Pacote p = new Pacote();
        p.raiz = destino;
        p.keys = new File(destino, "Keys");
        p.files = new File(destino, "Files");
        if (!p.keys.isDirectory() && !p.keys.mkdirs() || !p.files.isDirectory() && !p.files.mkdirs()) {
            throw new IOException("Nao foi possivel criar " + destino);
        }

        p.ca = new Identidade("ca", "AC INF1416", "ca@inf1416.puc-rio.br", null);
        p.ca.par = novoPar();
        p.ca.certificado = certificado(p.ca, p.ca, true, BigInteger.ONE);
        p.ca.arquivoCertificado = new File(p.keys, "ca-x509.crt");
        escrever(p.ca.arquivoCertificado, CriptoUtil.paraPem(p.ca.certificado).getBytes(StandardCharsets.US_ASCII));

        p.admin = usuario(p, "admin", "Administrador", ADMIN, FRASE_ADMIN, 2);
        p.user01 = usuario(p, "user01", "Usuario 01", USER01, FRASE_USER01, 3);
        p.user02 = usuario(p, "user02", "Usuario 02", USER02, FRASE_USER02, 4);

        gerarPastaSegura(p);
        escreverLeiaMe(p);
        return p;
    }

    private static Identidade usuario(Pacote p, String prefixo, String nome, String email, String frase, int serie)
            throws Exception {
        Identidade id = new Identidade(prefixo, nome, email, frase);
        id.par = novoPar();
        id.certificado = certificado(id, p.ca, false, BigInteger.valueOf(serie));
        id.arquivoCertificado = new File(p.keys, prefixo + "-x509.crt");
        id.arquivoChave = new File(p.keys, prefixo + "-pkcs8-aes.key");
        escrever(id.arquivoCertificado, CriptoUtil.paraPem(id.certificado).getBytes(StandardCharsets.US_ASCII));
        escrever(id.arquivoChave, cifrarChavePrivada(id.par.getPrivate(), frase));
        return id;
    }

    //
    // chave privada PKCS8 em BASE64 (PEM), cifrada com a chave AES da frase secreta
    public static byte[] cifrarChavePrivada(PrivateKey privada, String frase) throws GeneralSecurityException {
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                   + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(privada.getEncoded())
                   + "\n-----END PRIVATE KEY-----\n";
        return CriptoUtil.cifrarAES(CriptoUtil.chaveAES(frase.toCharArray()), pem.getBytes(StandardCharsets.US_ASCII));
    }

    // =====================================================================
    // Pasta segura
    // =====================================================================

    private static void gerarPastaSegura(Pacote p) throws Exception {
        File f = p.files;
        PublicKey adm = p.admin.par.getPublic(), u1 = p.user01.par.getPublic(), u2 = p.user02.par.getPublic();

        protegerArquivo(f, "XXYYZZ00", texto("Documento secreto do administrador."), adm, p.admin.par.getPrivate());
        byte[] s01 = protegerArquivo(f, "XXYYZZ01", texto("Documento secreto do user01 (compartilhado com o user02)."),
                                     u1, p.user01.par.getPrivate());
        criarEnvelope(new File(f, "XXYYZZ01_1.shr"), s01, u2);
        protegerArquivo(f, "XXYYZZ02", texto("Documento secreto do user02."), u2, p.user02.par.getPrivate());
        byte[] s03 = protegerArquivo(f, "XXYYZZ03", texto("Relatorio do administrador compartilhado com o user01."),
                                     adm, p.admin.par.getPrivate());
        criarEnvelope(new File(f, "XXYYZZ03_2.shr"), s03, u1);
        // assinatura digital de outro conteudo: falha de integridade/autenticidade
        protegerArquivo(f, "XXYYZZ04", texto("Conteudo original do user01."), u1, p.user01.par.getPrivate());
        escrever(new File(f, "XXYYZZ04.asd"), assinar(texto("Conteudo adulterado."), p.user01.par.getPrivate()));
        // envelope digital gerado para outro usuario: falha de decriptacao (sigilo)
        protegerArquivo(f, "XXYYZZ05", texto("Arquivo com envelope invalido."), u2, p.user01.par.getPrivate());

        String index = "XXYYZZ00 docAdmin.txt " + ADMIN + " administrador\n"
                     + "XXYYZZ01 docUser01.txt " + USER01 + " usuario\n"
                     + "XXYYZZ02 docUser02.txt " + USER02 + " usuario\n"
                     + "XXYYZZ03 relatorioAdmin.txt " + ADMIN + " administrador\n"
                     + "XXYYZZ04 assinaturaInvalida.txt " + USER01 + " usuario\n"
                     + "XXYYZZ05 envelopeInvalido.txt " + USER01 + " usuario\n";
        String share = "XXYYZZ01 1 " + USER02 + "\n"
                     + "XXYYZZ03 2 " + USER01 + "\n";
        protegerArquivo(f, "index", texto(index), adm, p.admin.par.getPrivate());
        protegerArquivo(f, "share", texto(share), adm, p.admin.par.getPrivate());
    }

    //
    // gera nome.enc (AES/ECB/PKCS5Padding com chave gerada por SHA1PRNG a partir de
    // uma semente aleatoria), nome.env (semente cifrada com a chave publica do
    // destinatario) e nome.asd (assinatura digital do conteudo); retorna a semente
    public static byte[] protegerArquivo(File pasta, String nome, byte[] conteudo, PublicKey destinatario,
                                         PrivateKey assinante) throws Exception {
        byte[] semente = new byte[32];
        new SecureRandom().nextBytes(semente);
        escrever(new File(pasta, nome + ".enc"), CriptoUtil.cifrarAES(CriptoUtil.chaveAES(semente), conteudo));
        criarEnvelope(new File(pasta, nome + ".env"), semente, destinatario);
        escrever(new File(pasta, nome + ".asd"), assinar(conteudo, assinante));
        return semente;
    }

    public static void criarEnvelope(File arquivo, byte[] semente, PublicKey destinatario) throws Exception {
        Cipher cipher = Cipher.getInstance(CriptoUtil.CIFRA_ENVELOPE);
        cipher.init(Cipher.ENCRYPT_MODE, destinatario);
        escrever(arquivo, cipher.doFinal(semente));
    }

    public static byte[] assinar(byte[] conteudo, PrivateKey privada) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(ASSINATURA);
        sig.initSign(privada);
        sig.update(conteudo);
        return sig.sign();
    }

    // =====================================================================
    // Certificados (BouncyCastle PKIX)
    // =====================================================================

    private static KeyPair novoPar() throws GeneralSecurityException {
        KeyPairGenerator gerador = KeyPairGenerator.getInstance("RSA");
        gerador.initialize(2048);
        return gerador.generateKeyPair();
    }

    private static X500Name nome(Identidade id) {
        return new X500NameBuilder(BCStyle.INSTANCE)
            .addRDN(BCStyle.C, "BR")
            .addRDN(BCStyle.ST, "Rio de Janeiro")
            .addRDN(BCStyle.L, "Rio de Janeiro")
            .addRDN(BCStyle.O, "PUC-Rio")
            .addRDN(BCStyle.OU, "INF1416")
            .addRDN(BCStyle.CN, id.nome)
            .addRDN(BCStyle.EmailAddress, id.email)
            .build();
    }

    private static X509Certificate certificado(Identidade sujeito, Identidade emissor, boolean ac, BigInteger serie)
            throws Exception {
        long agora = System.currentTimeMillis();
        Date inicio = new Date(agora - 24L * 3600 * 1000);
        Date fim = new Date(agora + 10L * 365 * 24 * 3600 * 1000);
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            nome(emissor), serie, inicio, fim, nome(sujeito), sujeito.par.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ac));
        return new JcaX509CertificateConverter().getCertificate(
            builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(emissor.par.getPrivate())));
    }

    // =====================================================================
    // Auxiliares
    // =====================================================================

    private static void escreverLeiaMe(Pacote p) throws IOException {
        String s = "Pacote de teste do Cofre Digital (gerado por GeradorPacote)\n\n"
                 + "Usuario   Certificado              Chave privada                 Frase secreta\n"
                 + "admin     Keys/admin-x509.crt      Keys/admin-pkcs8-aes.key      " + FRASE_ADMIN + "\n"
                 + "user01    Keys/user01-x509.crt     Keys/user01-pkcs8-aes.key     " + FRASE_USER01 + "\n"
                 + "user02    Keys/user02-x509.crt     Keys/user02-pkcs8-aes.key     " + FRASE_USER02 + "\n\n"
                 + "Pasta segura: Files/\n"
                 + "  XXYYZZ00 docAdmin.txt            dono admin,  grupo administrador\n"
                 + "  XXYYZZ01 docUser01.txt           dono user01, grupo usuario (compartilhado com user02, id 1)\n"
                 + "  XXYYZZ02 docUser02.txt           dono user02, grupo usuario\n"
                 + "  XXYYZZ03 relatorioAdmin.txt      dono admin,  grupo administrador (compartilhado com user01, id 2)\n"
                 + "  XXYYZZ04 assinaturaInvalida.txt  dono user01: assinatura digital nao confere (falha de verificacao)\n"
                 + "  XXYYZZ05 envelopeInvalido.txt    dono user01: envelope gerado para o user02 (falha de decriptacao)\n";
        escrever(new File(p.raiz, "LEIA-ME.txt"), s.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] texto(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static void escrever(File arquivo, byte[] dados) throws IOException {
        Files.write(arquivo.toPath(), dados);
    }
}
