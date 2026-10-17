import static org.junit.Assert.*;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.X509Certificate;
import javax.crypto.SecretKey;
import org.junit.*;

//
// Rotinas criptograficas: chave AES (SHA1PRNG), chave privada, certificado,
// envelope digital e assinatura digital
public class CriptoUtilTest {

    private static GeradorPacote.Pacote p;

    @BeforeClass
    public static void pacote() throws Exception {
        p = Cenario.pacote();
    }

    @Test
    public void chaveAESDe256BitsDeterministicaPelaSemente() throws Exception {
        SecretKey a = CriptoUtil.chaveAES("frase secreta".toCharArray());
        SecretKey b = CriptoUtil.chaveAES("frase secreta".toCharArray());
        SecretKey c = CriptoUtil.chaveAES("frase secretA".toCharArray());
        assertEquals(32, a.getEncoded().length);
        assertEquals("AES", a.getAlgorithm());
        assertArrayEquals(a.getEncoded(), b.getEncoded());
        assertFalse(java.util.Arrays.equals(a.getEncoded(), c.getEncoded()));
    }

    @Test
    public void cifraAESEcbPkcs5() throws Exception {
        SecretKey k = CriptoUtil.chaveAES(new byte[] {1, 2, 3});
        byte[] texto = "conteudo secreto".getBytes(StandardCharsets.UTF_8);
        byte[] cifrado = CriptoUtil.cifrarAES(k, texto);
        assertEquals(32, cifrado.length);   // 16 bytes + bloco de enchimento PKCS5
        assertArrayEquals(texto, CriptoUtil.decifrarAES(k, cifrado));
    }

    @Test
    public void decifraAChavePrivadaComAFraseSecretaCorreta() throws Exception {
        byte[] arquivo = Files.readAllBytes(p.user01.arquivoChave.toPath());
        PrivateKey k = CriptoUtil.decifrarChavePrivada(arquivo, "user01".toCharArray());
        assertEquals("RSA", k.getAlgorithm());
        assertEquals("PKCS#8", k.getFormat());
        assertArrayEquals(p.user01.par.getPrivate().getEncoded(), k.getEncoded());
    }

    @Test(expected = GeneralSecurityException.class)
    public void fraseSecretaErradaNaoDecifraAChavePrivada() throws Exception {
        CriptoUtil.decifrarChavePrivada(Files.readAllBytes(p.user01.arquivoChave.toPath()), "user02".toCharArray());
    }

    @Test
    public void aceitaChavePrivadaDecriptadaSemCabecalhoPem() throws Exception {
        String base64 = java.util.Base64.getEncoder().encodeToString(p.user02.par.getPrivate().getEncoded());
        byte[] arquivo = CriptoUtil.cifrarAES(CriptoUtil.chaveAES("x".toCharArray()),
                                              base64.getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals(p.user02.par.getPrivate().getEncoded(),
                          CriptoUtil.decifrarChavePrivada(arquivo, "x".toCharArray()).getEncoded());
    }

    @Test
    public void validarChavePrivadaRetornaCadaStatus() throws Exception {
        byte[] chave01 = Files.readAllBytes(p.user01.arquivoChave.toPath());
        assertEquals(CriptoUtil.StatusChave.OK, CriptoUtil.validarChavePrivada(
            chave01, "user01".toCharArray(), p.user01.certificado, CriptoUtil.TESTE_CADASTRO).status);
        assertEquals(CriptoUtil.StatusChave.FRASE_INVALIDA, CriptoUtil.validarChavePrivada(
            chave01, "errada".toCharArray(), p.user01.certificado, CriptoUtil.TESTE_CADASTRO).status);
        assertEquals(CriptoUtil.StatusChave.ASSINATURA_INVALIDA, CriptoUtil.validarChavePrivada(
            chave01, "user01".toCharArray(), p.user02.certificado, CriptoUtil.TESTE_CADASTRO).status);
        assertEquals(CriptoUtil.StatusChave.CAMINHO_INVALIDO, CriptoUtil.validarChavePrivada(
            null, "user01".toCharArray(), p.user01.certificado, CriptoUtil.TESTE_CADASTRO).status);
    }

    @Test
    public void verificacaoDoParDeChavesComArraysDe10240E2048Bytes() throws Exception {
        assertTrue(CriptoUtil.verificarParDeChaves(p.admin.par.getPrivate(), p.admin.certificado.getPublicKey(), 10240));
        assertTrue(CriptoUtil.verificarParDeChaves(p.admin.par.getPrivate(), p.admin.certificado.getPublicKey(), 2048));
        assertFalse(CriptoUtil.verificarParDeChaves(p.admin.par.getPrivate(), p.user01.certificado.getPublicKey(), 2048));
    }

    @Test
    public void extraiNomeEEmailDoSujeitoDoCertificado() throws Exception {
        X509Certificate cert = CriptoUtil.carregarCertificado(p.user01.arquivoCertificado);
        assertEquals("user01@inf1416.puc-rio.br", CriptoUtil.extrairEmail(cert));
        assertEquals("Usuario 01", CriptoUtil.extrairNome(cert));
        assertEquals("AC INF1416", CriptoUtil.atributo(cert.getIssuerX500Principal(), "CN"));
    }

    @Test
    public void certificadoEmFormatoPem() throws Exception {
        String pem = CriptoUtil.paraPem(p.admin.certificado);
        assertTrue(pem.startsWith("-----BEGIN CERTIFICATE-----\n"));
        assertTrue(pem.endsWith("-----END CERTIFICATE-----\n"));
        assertEquals(p.admin.certificado, CriptoUtil.certificadoDePem(pem));
    }

    @Test
    public void emailValido() {
        assertTrue(CriptoUtil.emailValido("admin@inf1416.puc-rio.br"));
        assertFalse(CriptoUtil.emailValido("admin"));
        assertFalse(CriptoUtil.emailValido("admin@"));
        assertFalse(CriptoUtil.emailValido("a b@c.com"));
        assertFalse(CriptoUtil.emailValido(null));
    }

    @Test
    public void envelopeDigitalProtegeASementeDaChaveAES() throws Exception {
        File pasta = Files.createTempDirectory("envelope").toFile();
        Cenario.apagarAoSair(pasta);
        byte[] texto = "segredo".getBytes(StandardCharsets.UTF_8);
        GeradorPacote.protegerArquivo(pasta, "teste", texto, p.user01.par.getPublic(), p.user01.par.getPrivate());
        byte[] enc = Files.readAllBytes(new File(pasta, "teste.enc").toPath());
        byte[] env = Files.readAllBytes(new File(pasta, "teste.env").toPath());
        assertArrayEquals(texto, CriptoUtil.decifrarComEnvelope(enc, env, p.user01.par.getPrivate()));
        try {
            CriptoUtil.decifrarComEnvelope(enc, env, p.user02.par.getPrivate());
            fail("o envelope so pode ser aberto pelo destinatario");
        } catch (GeneralSecurityException e) {
            // esperado
        }
    }

    @Test
    public void assinaturaDigitalDetectaAlteracaoEAssinanteErrado() throws Exception {
        byte[] dados = "dados".getBytes(StandardCharsets.UTF_8);
        byte[] asd = GeradorPacote.assinar(dados, p.admin.par.getPrivate());
        assertTrue(CriptoUtil.verificarAssinatura(dados, asd, p.admin.par.getPublic()));
        assertFalse(CriptoUtil.verificarAssinatura("dadoS".getBytes(StandardCharsets.UTF_8), asd, p.admin.par.getPublic()));
        assertFalse(CriptoUtil.verificarAssinatura(dados, asd, p.user01.par.getPublic()));
        asd[10] ^= 1;
        assertFalse(CriptoUtil.verificarAssinatura(dados, asd, p.admin.par.getPublic()));
    }

    @Test
    public void aceitaAssinaturasSha1ESha512ComRsa() throws Exception {
        byte[] dados = "dados".getBytes(StandardCharsets.UTF_8);
        for (String algoritmo : new String[] {"SHA1withRSA", "SHA512withRSA"}) {
            Signature s = Signature.getInstance(algoritmo);
            s.initSign(p.user02.par.getPrivate());
            s.update(dados);
            assertTrue(algoritmo, CriptoUtil.verificarAssinatura(dados, s.sign(), p.user02.par.getPublic()));
        }
    }

    @Test
    public void lerArquivoComCaminhoInvalidoRetornaNull() {
        assertNull(CriptoUtil.lerArquivo(null));
        assertNull(CriptoUtil.lerArquivo(""));
        assertNull(CriptoUtil.lerArquivo("/caminho/que/nao/existe.key"));
        assertNull(CriptoUtil.lerArquivo(p.keys.getPath()));
    }
}
