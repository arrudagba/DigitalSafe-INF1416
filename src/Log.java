// Gabriel de Barros Arruda - 2311723
// Erica Oliveira Regnier - 2211893

import java.sql.SQLException;
import java.util.function.LongSupplier;

public class Log {

    private final Banco banco;
    private final LongSupplier relogio;

    public Log(Banco banco, LongSupplier relogio) {
        this.banco = banco;
        this.relogio = relogio;
    }

    public void registrar(int mid) {
        gravar(mid, null, null, null);
    }

    public void registrar(int mid, Usuario usuario) {
        gravar(mid, usuario, null, null);
    }

    public void registrar(int mid, Usuario usuario, String arquivo) {
        gravar(mid, usuario, null, arquivo);
    }

    public void registrar(int mid, String loginName) {
        gravar(mid, null, loginName, null);
    }

    private void gravar(int mid, Usuario usuario, String loginName, String arquivo) {
        try {
            banco.registrar(relogio.getAsLong(), mid, usuario != null ? usuario.uid : null, loginName, arquivo);
        } catch (SQLException e) {
            throw new IllegalStateException("Falha ao gravar o registro " + mid + ": " + e.getMessage(), e);
        }
    }
}
