// Gabriel de Barros Arruda - 2311723
// Erica Oliveira Regnier - 2211893

import java.io.*;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.*;

public class LogView {

    public static void main(String[] args) {
        if (args.length < 1 || args.length > 2) {
            System.err.println("Usage: java LogView Caminho_Chave_Privada_Administrador [Caminho_Banco_de_Dados]");
            System.err.println("       (banco de dados padrao: " + Banco.ARQUIVO_PADRAO + ")");
            System.exit(1);
        }
        String caminhoBanco = args.length == 2 ? args[1] : Banco.ARQUIVO_PADRAO;
        if (!new File(caminhoBanco).isFile()) {
            System.err.println("Banco de dados do Cofre Digital nao encontrado: " + caminhoBanco);
            System.exit(1);
        }
        Console console = System.console();
        if (console == null) {
            System.err.println("O LogView deve ser executado em um terminal (a frase secreta eh lida sem echo).");
            System.exit(1);
        }
        char[] frase = console.readPassword("Frase secreta da chave privada do administrador: ");
        if (frase == null) {
            System.exit(1);
        }

        int codigo;
        try (Banco banco = new Banco(caminhoBanco)) {
            Usuario admin = autenticar(banco, args[0], frase);
            Arrays.fill(frase, '\0');
            if (admin == null) {
                System.err.println("Chave privada verificada negativamente. O LogView sera encerrado.");
                codigo = 1;
            } else {
                imprimir(banco, System.out);
                codigo = 0;
            }
        } catch (SQLException e) {
            System.err.println("Erro no banco de dados: " + e.getMessage());
            codigo = 1;
        } finally {
            Arrays.fill(frase, '\0');
        }
        System.exit(codigo);
    }

    static Usuario autenticar(Banco banco, String caminhoChave, char[] frase) throws SQLException {
        byte[] chaveCifrada = CriptoUtil.lerArquivo(caminhoChave);
        if (chaveCifrada == null) {
            return null;
        }
        for (Usuario admin : banco.administradores()) {
            try {
                X509Certificate certificado = CriptoUtil.certificadoDePem(banco.certificadoPem(admin.kid));
                CriptoUtil.ResultadoChave r = CriptoUtil.validarChavePrivada(chaveCifrada, frase, certificado,
                                                                             CriptoUtil.TESTE_LOGVIEW);
                if (r.status == CriptoUtil.StatusChave.OK) {
                    return admin;
                }
                if (r.status == CriptoUtil.StatusChave.FRASE_INVALIDA) {
                    return null;
                }
            } catch (java.security.cert.CertificateException e) {
                // certificado invalido: tenta o proximo administrador
            }
        }
        return null;
    }

    static void imprimir(Banco banco, PrintStream out) throws SQLException {
        SimpleDateFormat formato = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss.SSS");
        List<Banco.Registro> registros = banco.registrosCronologicos();
        out.println("Registros do Cofre Digital (" + registros.size() + "), em ordem cronologica:");
        out.println("Data       Hora          Codigo  Mensagem");
        for (Banco.Registro r : registros) {
            out.println(formato.format(new Date(r.dataHora)) + "  " + r.mid + "    " + r.getMensagem());
        }
    }
}
