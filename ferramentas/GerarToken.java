// Gabriel de Barros Arruda - 2311723
// Erica Oliveira Regnier - 2211893

public class GerarToken {

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: java GerarToken Chave_Secreta_BASE32");
            System.exit(1);
        }
        TOTP totp = new TOTP(args[0], 30);
        long restante = 30 - (System.currentTimeMillis() / 1000) % 30;
        System.out.println(totp.generateCode() + "  (valido por mais " + restante + " s)");
    }
}
