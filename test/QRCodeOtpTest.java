// Gabriel de Barros Arruda - 2311723
// Erica Oliveira Regnier - 2211893

import static org.junit.Assert.*;

import java.awt.image.BufferedImage;
import org.junit.*;
import com.google.zxing.*;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;

public class QRCodeOtpTest {

    @Test
    public void qrCodeContemAUriOtpAuthDoEnunciado() throws Exception {
        String uri = "otpauth://totp/Cofre%20Digital:admin@inf1416.puc-rio.br?secret=JXXMGK33L7S3H3JOY5GMUXC7G7ASJHTD";
        assertEquals(uri, ler(QRCodeOtp.gerar(uri, 260)));
    }

    @Test
    public void qrCodeDoCadastroPermiteGerarOMesmoTokenQueOSistemaValida() throws Exception {
        try (Cenario c = new Cenario()) {
            c.sistema.iniciar();
            Cadastro.Confirmacao conf = c.cadastrar(c.p().admin, Cenario.SENHA_ADMIN, Usuario.GID_ADMINISTRADOR, null);
            String lida = ler(QRCodeOtp.gerar(conf.uriOtpAuth, 260));
            assertEquals(conf.uriOtpAuth, lida);
            // segredo do parametro secret
            String segredo = lida.substring(lida.indexOf("secret=") + 7);
            assertEquals(conf.segredoTotpBase32, segredo);
            assertTrue(new TOTP(c.segredos.get(GeradorPacote.ADMIN), 30).validateCode(new TOTP(segredo, 30).generateCode()));
        }
    }

    @Test
    public void imagemQuadradaPretoEBrancoNoTamanhoPedido() throws Exception {
        BufferedImage img = QRCodeOtp.gerar("otpauth://totp/Cofre%20Digital:a@b.com?secret=MZXW6YTBOI", 300);
        assertEquals(300, img.getWidth());
        assertEquals(300, img.getHeight());
        for (int y = 0; y < img.getHeight(); y += 7) {
            for (int x = 0; x < img.getWidth(); x += 7) {
                int rgb = img.getRGB(x, y) & 0xFFFFFF;
                assertTrue(rgb == 0x000000 || rgb == 0xFFFFFF);
            }
        }
    }

    private static String ler(BufferedImage img) throws Exception {
        int[] pixels = img.getRGB(0, 0, img.getWidth(), img.getHeight(), null, 0, img.getWidth());
        LuminanceSource fonte = new RGBLuminanceSource(img.getWidth(), img.getHeight(), pixels);
        return new QRCodeReader().decode(new BinaryBitmap(new HybridBinarizer(fonte))).getText();
    }
}
