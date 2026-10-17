//
// Registro de um usuario da tabela Usuarios
public class Usuario {

    public static final int GID_ADMINISTRADOR = 1;
    public static final int GID_USUARIO       = 2;

    int uid;
    String nome;
    String loginName;
    int gid;
    String grupo;
    Integer kid;
    String senha;
    byte[] chaveTotp;
    int totalAcessos;
    int totalConsultas;
    int errosSenha;
    int errosToken;
    long bloqueadoAte;

    public int getUid()            { return uid; }
    public String getNome()        { return nome; }
    public String getLoginName()   { return loginName; }
    public int getGid()            { return gid; }
    public String getGrupo()       { return grupo; }
    public Integer getKid()        { return kid; }
    public int getTotalAcessos()   { return totalAcessos; }
    public int getTotalConsultas() { return totalConsultas; }

    public boolean isAdministrador() {
        return gid == GID_ADMINISTRADOR;
    }

    public boolean isBloqueado(long agora) {
        return bloqueadoAte > agora;
    }
}
