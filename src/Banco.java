import java.sql.*;
import java.util.*;

//
// Banco de dados relacional (SQLite) do Cofre Digital, com as tabelas Usuarios,
// Chaveiro, Grupos, Mensagens e Registros
public class Banco implements AutoCloseable {

    public static final String ARQUIVO_PADRAO = "cofre.db";

    private final Connection con;

    //
    // linha da tabela Registros com o texto da mensagem obtido da tabela Mensagens
    public static class Registro {
        public final int rid;
        public final long dataHora;
        public final int mid;
        public final String texto;
        public final String loginName;
        public final String arquivo;

        Registro(int rid, long dataHora, int mid, String texto, String loginName, String arquivo) {
            this.rid = rid;
            this.dataHora = dataHora;
            this.mid = mid;
            this.texto = texto;
            this.loginName = loginName;
            this.arquivo = arquivo;
        }

        public String getMensagem() {
            return Mensagens.formatar(texto, loginName, arquivo);
        }
    }

    public Banco(String caminho) throws SQLException {
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            throw new SQLException("Driver SQLite (sqlite-jdbc) nao encontrado no classpath.", e);
        }
        con = DriverManager.getConnection("jdbc:sqlite:" + caminho);
        try (Statement st = con.createStatement()) {
            st.execute("PRAGMA foreign_keys = ON");
            st.execute("PRAGMA journal_mode = WAL");
        }
        criarEsquema();
    }

    private void criarEsquema() throws SQLException {
        // criacao das tabelas e carga de Grupos/Mensagens em uma unica transacao
        con.setAutoCommit(false);
        try {
            criarTabelas();
            con.commit();
        } catch (SQLException e) {
            con.rollback();
            throw e;
        } finally {
            con.setAutoCommit(true);
        }
    }

    private void criarTabelas() throws SQLException {
        try (Statement st = con.createStatement()) {
            st.execute("CREATE TABLE IF NOT EXISTS Grupos ("
                     + " gid  INTEGER PRIMARY KEY,"
                     + " nome TEXT NOT NULL UNIQUE)");
            st.execute("CREATE TABLE IF NOT EXISTS Usuarios ("
                     + " uid             INTEGER PRIMARY KEY AUTOINCREMENT,"
                     + " nome            TEXT NOT NULL,"
                     + " login_name      TEXT NOT NULL UNIQUE COLLATE NOCASE,"
                     + " gid             INTEGER NOT NULL REFERENCES Grupos(gid),"
                     + " kid             INTEGER REFERENCES Chaveiro(kid),"
                     + " senha           TEXT NOT NULL,"
                     + " chave_totp      BLOB NOT NULL,"
                     + " total_acessos   INTEGER NOT NULL DEFAULT 0,"
                     + " total_consultas INTEGER NOT NULL DEFAULT 0,"
                     + " erros_senha     INTEGER NOT NULL DEFAULT 0,"
                     + " erros_token     INTEGER NOT NULL DEFAULT 0,"
                     + " bloqueado_ate   INTEGER NOT NULL DEFAULT 0)");
            st.execute("CREATE TABLE IF NOT EXISTS Chaveiro ("
                     + " kid             INTEGER PRIMARY KEY AUTOINCREMENT,"
                     + " uid             INTEGER NOT NULL REFERENCES Usuarios(uid),"
                     + " certificado_pem TEXT NOT NULL,"
                     + " chave_privada   BLOB NOT NULL)");
            st.execute("CREATE TABLE IF NOT EXISTS Mensagens ("
                     + " mid   INTEGER PRIMARY KEY,"
                     + " texto TEXT NOT NULL)");
            st.execute("CREATE TABLE IF NOT EXISTS Registros ("
                     + " rid        INTEGER PRIMARY KEY AUTOINCREMENT,"
                     + " data_hora  INTEGER NOT NULL,"
                     + " mid        INTEGER NOT NULL REFERENCES Mensagens(mid),"
                     + " uid        INTEGER REFERENCES Usuarios(uid),"
                     + " login_name TEXT,"
                     + " arquivo    TEXT)");
        }
        try (PreparedStatement ps = con.prepareStatement("INSERT OR IGNORE INTO Grupos (gid, nome) VALUES (?, ?)")) {
            ps.setInt(1, Usuario.GID_ADMINISTRADOR);
            ps.setString(2, "Administrador");
            ps.executeUpdate();
            ps.setInt(1, Usuario.GID_USUARIO);
            ps.setString(2, "Usuário");
            ps.executeUpdate();
        }
        try (PreparedStatement ps = con.prepareStatement("INSERT OR REPLACE INTO Mensagens (mid, texto) VALUES (?, ?)")) {
            for (Map.Entry<Integer, String> m : Mensagens.TABELA.entrySet()) {
                ps.setInt(1, m.getKey());
                ps.setString(2, m.getValue());
                ps.addBatch();
            }
            ps.executeBatch();
        }
    }

    Connection getConexao() {
        return con;
    }

    // =====================================================================
    // Usuarios e Chaveiro
    // =====================================================================

    public int totalUsuarios() throws SQLException {
        try (Statement st = con.createStatement();
             ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM Usuarios")) {
            return rs.getInt(1);
        }
    }

    private static final String SELECT_USUARIO =
        "SELECT u.uid, u.nome, u.login_name, u.gid, g.nome AS grupo, u.kid, u.senha, u.chave_totp,"
      + " u.total_acessos, u.total_consultas, u.erros_senha, u.erros_token, u.bloqueado_ate"
      + " FROM Usuarios u JOIN Grupos g ON g.gid = u.gid";

    public Usuario buscarUsuario(String loginName) throws SQLException {
        if (loginName == null) {
            return null;
        }
        try (PreparedStatement ps = con.prepareStatement(SELECT_USUARIO + " WHERE u.login_name = ?")) {
            ps.setString(1, loginName.trim());
            return umUsuario(ps);
        }
    }

    public Usuario buscarUsuario(int uid) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement(SELECT_USUARIO + " WHERE u.uid = ?")) {
            ps.setInt(1, uid);
            return umUsuario(ps);
        }
    }

    //
    // administrador do sistema: o primeiro administrador cadastrado (partida do sistema)
    public Usuario administradorDoSistema() throws SQLException {
        try (PreparedStatement ps = con.prepareStatement(SELECT_USUARIO + " WHERE u.gid = ? ORDER BY u.uid LIMIT 1")) {
            ps.setInt(1, Usuario.GID_ADMINISTRADOR);
            return umUsuario(ps);
        }
    }

    public List<Usuario> administradores() throws SQLException {
        List<Usuario> lista = new ArrayList<Usuario>();
        try (PreparedStatement ps = con.prepareStatement(SELECT_USUARIO + " WHERE u.gid = ? ORDER BY u.uid")) {
            ps.setInt(1, Usuario.GID_ADMINISTRADOR);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    lista.add(lerUsuario(rs));
                }
            }
        }
        return lista;
    }

    private Usuario umUsuario(PreparedStatement ps) throws SQLException {
        try (ResultSet rs = ps.executeQuery()) {
            return rs.next() ? lerUsuario(rs) : null;
        }
    }

    private static Usuario lerUsuario(ResultSet rs) throws SQLException {
        Usuario u = new Usuario();
        u.uid = rs.getInt("uid");
        u.nome = rs.getString("nome");
        u.loginName = rs.getString("login_name");
        u.gid = rs.getInt("gid");
        u.grupo = rs.getString("grupo");
        int kid = rs.getInt("kid");
        u.kid = rs.wasNull() ? null : kid;
        u.senha = rs.getString("senha");
        u.chaveTotp = rs.getBytes("chave_totp");
        u.totalAcessos = rs.getInt("total_acessos");
        u.totalConsultas = rs.getInt("total_consultas");
        u.errosSenha = rs.getInt("erros_senha");
        u.errosToken = rs.getInt("erros_token");
        u.bloqueadoAte = rs.getLong("bloqueado_ate");
        return u;
    }

    public String nomeGrupo(int gid) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement("SELECT nome FROM Grupos WHERE gid = ?")) {
            ps.setInt(1, gid);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        }
    }

    //
    // inclui o usuario e o seu par certificado digital / chave privada (KID) no
    // Chaveiro, guardando o KID no registro do usuario
    public int inserirUsuario(String nome, String loginName, int gid, String senhaBcrypt, byte[] chaveTotpCifrada,
                              String certificadoPem, byte[] chavePrivadaCifrada) throws SQLException {
        boolean autoCommit = con.getAutoCommit();
        con.setAutoCommit(false);
        try {
            int uid;
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO Usuarios (nome, login_name, gid, senha, chave_totp) VALUES (?, ?, ?, ?, ?)",
                    Statement.RETURN_GENERATED_KEYS)) {
                ps.setString(1, nome);
                ps.setString(2, loginName);
                ps.setInt(3, gid);
                ps.setString(4, senhaBcrypt);
                ps.setBytes(5, chaveTotpCifrada);
                ps.executeUpdate();
                uid = chaveGerada(ps);
            }
            int kid;
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO Chaveiro (uid, certificado_pem, chave_privada) VALUES (?, ?, ?)",
                    Statement.RETURN_GENERATED_KEYS)) {
                ps.setInt(1, uid);
                ps.setString(2, certificadoPem);
                ps.setBytes(3, chavePrivadaCifrada);
                ps.executeUpdate();
                kid = chaveGerada(ps);
            }
            try (PreparedStatement ps = con.prepareStatement("UPDATE Usuarios SET kid = ? WHERE uid = ?")) {
                ps.setInt(1, kid);
                ps.setInt(2, uid);
                ps.executeUpdate();
            }
            con.commit();
            return uid;
        } catch (SQLException e) {
            con.rollback();
            throw e;
        } finally {
            con.setAutoCommit(autoCommit);
        }
    }

    private static int chaveGerada(PreparedStatement ps) throws SQLException {
        try (ResultSet rs = ps.getGeneratedKeys()) {
            rs.next();
            return rs.getInt(1);
        }
    }

    public String certificadoPem(int kid) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement("SELECT certificado_pem FROM Chaveiro WHERE kid = ?")) {
            ps.setInt(1, kid);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        }
    }

    public byte[] chavePrivadaCifrada(int kid) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement("SELECT chave_privada FROM Chaveiro WHERE kid = ?")) {
            ps.setInt(1, kid);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getBytes(1) : null;
            }
        }
    }

    public void incrementarAcessos(int uid) throws SQLException {
        atualizar("UPDATE Usuarios SET total_acessos = total_acessos + 1 WHERE uid = ?", uid);
    }

    public void incrementarConsultas(int uid) throws SQLException {
        atualizar("UPDATE Usuarios SET total_consultas = total_consultas + 1 WHERE uid = ?", uid);
    }

    public void definirErrosSenha(int uid, int erros) throws SQLException {
        atualizar("UPDATE Usuarios SET erros_senha = ? WHERE uid = ?", erros, uid);
    }

    public void definirErrosToken(int uid, int erros) throws SQLException {
        atualizar("UPDATE Usuarios SET erros_token = ? WHERE uid = ?", erros, uid);
    }

    public void bloquear(int uid, long ate) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement(
                "UPDATE Usuarios SET bloqueado_ate = ?, erros_senha = 0, erros_token = 0 WHERE uid = ?")) {
            ps.setLong(1, ate);
            ps.setInt(2, uid);
            ps.executeUpdate();
        }
    }

    private void atualizar(String sql, int... valores) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement(sql)) {
            for (int i = 0; i < valores.length; i++) {
                ps.setInt(i + 1, valores[i]);
            }
            ps.executeUpdate();
        }
    }

    // =====================================================================
    // Registros
    // =====================================================================

    public void registrar(long dataHora, int mid, Integer uid, String loginName, String arquivo) throws SQLException {
        try (PreparedStatement ps = con.prepareStatement(
                "INSERT INTO Registros (data_hora, mid, uid, login_name, arquivo) VALUES (?, ?, ?, ?, ?)")) {
            ps.setLong(1, dataHora);
            ps.setInt(2, mid);
            if (uid != null) {
                ps.setInt(3, uid);
            } else {
                ps.setNull(3, Types.INTEGER);
            }
            ps.setString(4, uid != null ? null : loginName);
            ps.setString(5, arquivo);
            ps.executeUpdate();
        }
    }

    //
    // registros em ordem cronologica, com o texto vindo da tabela Mensagens e o
    // login name vindo da tabela Usuarios (ou o login informado nao identificado)
    public List<Registro> registrosCronologicos() throws SQLException {
        List<Registro> lista = new ArrayList<Registro>();
        String sql = "SELECT r.rid, r.data_hora, r.mid, m.texto, COALESCE(u.login_name, r.login_name) AS login, r.arquivo"
                   + " FROM Registros r JOIN Mensagens m ON m.mid = r.mid"
                   + " LEFT JOIN Usuarios u ON u.uid = r.uid"
                   + " ORDER BY r.data_hora, r.rid";
        try (Statement st = con.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            while (rs.next()) {
                lista.add(new Registro(rs.getInt(1), rs.getLong(2), rs.getInt(3), rs.getString(4),
                                       rs.getString(5), rs.getString(6)));
            }
        }
        return lista;
    }

    @Override
    public void close() throws SQLException {
        con.close();
    }
}
