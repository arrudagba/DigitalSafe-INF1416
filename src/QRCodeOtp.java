// Gabriel de Barros Arruda - 2311723
// Erica Oliveira Regnier - 2211893

import java.awt.image.BufferedImage;
import java.util.EnumMap;
import java.util.Map;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

public final class QRCodeOtp {

    private static final int PRETO  = 0xFF000000;
    private static final int BRANCO = 0xFFFFFFFF;

    private QRCodeOtp() {
    }

    public static BufferedImage gerar(String texto, int tamanho) throws WriterException {
        Map<EncodeHintType, Object> opcoes = new EnumMap<EncodeHintType, Object>(EncodeHintType.class);
        opcoes.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);
        opcoes.put(EncodeHintType.CHARACTER_SET, "UTF-8");
        opcoes.put(EncodeHintType.MARGIN, 2);
        BitMatrix matriz = new QRCodeWriter().encode(texto, BarcodeFormat.QR_CODE, tamanho, tamanho, opcoes);

        BufferedImage imagem = new BufferedImage(matriz.getWidth(), matriz.getHeight(), BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < matriz.getHeight(); y++) {
            for (int x = 0; x < matriz.getWidth(); x++) {
                imagem.setRGB(x, y, matriz.get(x, y) ? PRETO : BRANCO);
            }
        }
        return imagem;
    }
}
