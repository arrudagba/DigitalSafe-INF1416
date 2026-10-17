import java.awt.*;
import java.awt.event.*;
import java.sql.SQLException;
import java.util.*;
import java.util.List;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.*;

//
// Cofre Digital (Digital Vault): interface grafica. Toda a logica e os registros
// ficam no Sistema; esta classe apenas apresenta as telas.
@SuppressWarnings("serial")
public class CofreDigital extends JFrame {

    private static final int CAMPO_255 = Cadastro.TAMANHO_CAMPO;
    private static final int CAMPO_SENHA = Senha.TAMANHO_MAX;

    private final Sistema sistema;
    private final JPanel conteudo = new JPanel(new BorderLayout());

    // estado da Tela de Cadastro (formulario preenchido em caso de erro)
    private Cadastro.Formulario formularioAnterior;

    // estado da Tela de Consultar
    private Consulta.Listagem listagem;

    public static void main(String[] args) {
        final String caminhoBanco = args.length > 0 ? args[0] : Banco.ARQUIVO_PADRAO;
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                try {
                    new CofreDigital(new Sistema(caminhoBanco)).partida();
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(null, "Não foi possível iniciar o Cofre Digital:\n" + e.getMessage(),
                                                  "Cofre Digital", JOptionPane.ERROR_MESSAGE);
                    System.exit(1);
                }
            }
        });
    }

    CofreDigital(Sistema sistema) {
        super("Cofre Digital");
        this.sistema = sistema;
        setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                encerrarExecucao();
            }
        });
        conteudo.setBorder(BorderFactory.createEmptyBorder(16, 24, 16, 24));
        setContentPane(conteudo);
        setSize(820, 640);
        setLocationRelativeTo(null);
    }

    // =====================================================================
    // Processo de partida
    // =====================================================================

    void partida() throws SQLException {
        setVisible(true);
        if (sistema.iniciar() == Sistema.Partida.CADASTRO_ADMINISTRADOR) {
            formularioAnterior = null;
            telaCadastro(true);
            return;
        }
        JPasswordField campo = new JPasswordField(25);
        limitar(campo, CAMPO_255);
        int opcao = JOptionPane.showConfirmDialog(this, new Object[] {
                "Partida do sistema: informe a frase secreta da chave privada do administrador.", campo},
            "Cofre Digital", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
        char[] frase = campo.getPassword();
        try {
            if (opcao != JOptionPane.OK_OPTION || !sistema.validarFraseAdministrador(frase)) {
                erro("Frase secreta da chave privada do administrador inválida.\nO sistema será encerrado.");
                encerrarExecucao();
                return;
            }
        } finally {
            Arrays.fill(frase, '\0');
        }
        iniciarAutenticacao();
    }

    private void encerrarExecucao() {
        sistema.encerrar();
        try {
            sistema.close();
        } catch (SQLException e) {
            // encerrando de qualquer forma
        }
        dispose();
        System.exit(0);
    }

    // =====================================================================
    // Autenticacao
    // =====================================================================

    private void iniciarAutenticacao() {
        sistema.iniciarAutenticacao();
        telaEtapa1();
    }

    private void telaEtapa1() {
        final JTextField login = campo(30, CAMPO_255);
        JButton continuar = new JButton("Continuar");
        ActionListener acao = new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                rodar(new Acao() {
                    public void executar() throws Exception {
                        switch (sistema.getAutenticacao().identificar(login.getText())) {
                            case LIBERADO:
                                telaEtapa2();
                                break;
                            case BLOQUEADO:
                                aviso("O acesso deste usuário está bloqueado temporariamente.\nTente novamente mais tarde.");
                                login.selectAll();
                                break;
                            default:
                                aviso("Login name não identificado.");
                                login.selectAll();
                        }
                    }
                });
            }
        };
        continuar.addActionListener(acao);
        login.addActionListener(acao);

        JPanel corpo = formulario();
        linha(corpo, 0, "Login name (e-mail):", login);
        mostrar(painel(titulo("Autenticação – Etapa 1 de 3: identificação do usuário"), corpo, botoes(continuar)), login);
    }

    private void telaEtapa2() {
        final TecladoVirtual teclado = new TecladoVirtual();
        final JButton[] botoes = new JButton[TecladoVirtual.BOTOES];
        final JLabel senha = new JLabel(" ");
        senha.setFont(senha.getFont().deriveFont(Font.BOLD, 22f));
        final JButton apagar = new JButton("Apagar");
        final JButton limpar = new JButton("Limpar");
        final JButton verificar = new JButton("Verificar senha");

        final Runnable atualizar = new Runnable() {
            public void run() {
                for (int i = 0; i < botoes.length; i++) {
                    botoes[i].setText(teclado.getRotulo(i));
                }
                StringBuilder s = new StringBuilder();
                for (int i = 0; i < teclado.getQuantidade(); i++) {
                    s.append("● ");
                }
                senha.setText(s.length() == 0 ? " " : s.toString());
            }
        };

        JPanel teclas = new JPanel(new GridLayout(1, TecladoVirtual.BOTOES, 8, 8));
        for (int i = 0; i < botoes.length; i++) {
            final int indice = i;
            botoes[i] = new JButton();
            botoes[i].setFont(botoes[i].getFont().deriveFont(Font.BOLD, 18f));
            botoes[i].setPreferredSize(new Dimension(110, 60));
            botoes[i].addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    teclado.pressionar(indice);
                    atualizar.run();
                }
            });
            teclas.add(botoes[i]);
        }
        apagar.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                teclado.apagarUltimo();
                atualizar.run();
            }
        });
        limpar.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                teclado.limpar();
                atualizar.run();
            }
        });
        verificar.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                final List<char[]> pares = new ArrayList<char[]>(teclado.getPressionados());
                final List<JButton> todos = new ArrayList<JButton>(Arrays.asList(botoes));
                todos.addAll(Arrays.asList(apagar, limpar, verificar));
                habilitar(todos, false);
                verificar.setText("Verificando...");
                // a verificacao testa as combinacoes dos pares com bcrypt: fora da thread da interface
                new SwingWorker<Autenticacao.Resultado, Void>() {
                    protected Autenticacao.Resultado doInBackground() throws Exception {
                        return sistema.getAutenticacao().verificarSenha(pares);
                    }

                    protected void done() {
                        teclado.limpar();
                        atualizar.run();
                        habilitar(todos, true);
                        verificar.setText("Verificar senha");
                        try {
                            switch (get()) {
                                case SENHA_OK:
                                    telaEtapa3();
                                    break;
                                case BLOQUEADO:
                                    aviso("Senha pessoal inválida.\nTerceiro erro consecutivo: o acesso do usuário foi "
                                        + "bloqueado por 2 minutos.");
                                    telaEtapa1();
                                    break;
                                default:
                                    aviso("Senha pessoal inválida (erro " + errosSenha() + " de 3).");
                            }
                        } catch (Exception ex) {
                            erro("Erro na verificação da senha: " + ex.getMessage());
                        }
                    }
                }.execute();
            }
        });
        atualizar.run();

        JPanel corpo = new JPanel();
        corpo.setLayout(new BoxLayout(corpo, BoxLayout.Y_AXIS));
        corpo.add(rotulo("Login name: " + sistema.getAutenticacao().getUsuario().getLoginName()));
        corpo.add(Box.createVerticalStrut(12));
        corpo.add(rotulo("Digite a senha pessoal (8, 9 ou 10 números) no teclado virtual:"));
        corpo.add(Box.createVerticalStrut(8));
        teclas.setAlignmentX(LEFT_ALIGNMENT);
        corpo.add(teclas);
        corpo.add(Box.createVerticalStrut(12));
        senha.setAlignmentX(LEFT_ALIGNMENT);
        corpo.add(senha);
        mostrar(painel(titulo("Autenticação – Etapa 2 de 3: senha pessoal"), corpo, botoes(apagar, limpar, verificar)),
                null);
    }

    private int errosSenha() {
        Usuario u = sistema.getAutenticacao().getUsuario();
        return u == null ? 0 : u.errosSenha;
    }

    private void telaEtapa3() {
        final JTextField token = campo(10, 6);
        JButton verificar = new JButton("Verificar token");
        ActionListener acao = new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                rodar(new Acao() {
                    public void executar() throws Exception {
                        switch (sistema.getAutenticacao().verificarToken(token.getText())) {
                            case TOKEN_OK:
                                sistema.iniciarSessao();
                                telaPrincipal();
                                break;
                            case BLOQUEADO:
                                aviso("Token inválido.\nTerceiro erro consecutivo: o acesso do usuário foi bloqueado "
                                    + "por 2 minutos.");
                                telaEtapa1();
                                break;
                            default:
                                aviso("Token inválido (erro " + sistema.getAutenticacao().getUsuario().errosToken
                                    + " de 3).");
                                token.setText("");
                                token.requestFocusInWindow();
                        }
                    }
                });
            }
        };
        verificar.addActionListener(acao);
        token.addActionListener(acao);

        JPanel corpo = formulario();
        linha(corpo, 0, "Login name:", rotulo(sistema.getAutenticacao().getUsuario().getLoginName()));
        linha(corpo, 1, "Código TOTP (Google Authenticator):", token);
        mostrar(painel(titulo("Autenticação – Etapa 3 de 3: token"), corpo, botoes(verificar)), token);
    }

    // =====================================================================
    // Tela Principal
    // =====================================================================

    private void telaPrincipal() {
        rodar(new Acao() {
            public void executar() throws Exception {
                Usuario u = sistema.atualizarUsuarioSessao();
                sistema.telaPrincipal();

                JPanel menu = new JPanel();
                menu.setLayout(new BoxLayout(menu, BoxLayout.Y_AXIS));
                menu.add(rotulo("Menu Principal:"));
                menu.add(Box.createVerticalStrut(10));
                if (u.isAdministrador()) {
                    menu.add(botaoMenu("1 – Cadastrar um novo usuário", new Runnable() {
                        public void run() {
                            sistema.opcaoCadastrar();
                            formularioAnterior = null;
                            telaCadastro(false);
                        }
                    }));
                }
                menu.add(botaoMenu("2 – Consultar pasta de arquivos secretos do usuário", new Runnable() {
                    public void run() {
                        sistema.opcaoConsultar();
                        telaConsulta();
                    }
                }));
                menu.add(botaoMenu("3 – Sair do Sistema", new Runnable() {
                    public void run() {
                        sistema.opcaoSair();
                        telaSaida();
                    }
                }));
                mostrar(painel(cabecalho(u), rotulo("Total de acessos do usuário: " + u.getTotalAcessos()), menu),
                        null);
            }
        });
    }

    // =====================================================================
    // Tela de Cadastro (opcao 1 e cadastro do administrador na partida)
    // =====================================================================

    private void telaCadastro(final boolean partida) {
        rodar(new Acao() {
            public void executar() throws Exception {
                if (!partida) {
                    sistema.telaCadastro();
                }
                final JTextField certificado = campo(40, CAMPO_255);
                final JTextField chave = campo(40, CAMPO_255);
                final JPasswordField frase = new JPasswordField(40);
                limitar(frase, CAMPO_255);
                final JComboBox<String> grupo = new JComboBox<String>(new String[] {"Administrador", "Usuário"});
                final JPasswordField senha = new JPasswordField(12);
                final JPasswordField confirmacao = new JPasswordField(12);
                limitar(senha, CAMPO_SENHA);
                limitar(confirmacao, CAMPO_SENHA);
                if (partida) {
                    grupo.setSelectedIndex(0);
                    grupo.setEnabled(false);
                } else {
                    grupo.setSelectedIndex(1);
                }
                Cadastro.Formulario anterior = formularioAnterior;
                if (anterior != null) {
                    certificado.setText(anterior.caminhoCertificado);
                    chave.setText(anterior.caminhoChavePrivada);
                    frase.setText(new String(anterior.fraseSecreta));
                    grupo.setSelectedIndex(anterior.gid == Usuario.GID_ADMINISTRADOR ? 0 : 1);
                    senha.setText(new String(anterior.senha));
                    confirmacao.setText(new String(anterior.confirmacaoSenha));
                    anterior.apagar();
                    formularioAnterior = null;
                }

                JButton cadastrar = new JButton("Cadastrar");
                JButton voltar = new JButton(partida ? "Encerrar Sistema"
                                                     : "Voltar de Cadastrar para o Menu Principal");
                cadastrar.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        Cadastro.Formulario f = new Cadastro.Formulario();
                        f.caminhoCertificado = certificado.getText();
                        f.caminhoChavePrivada = chave.getText();
                        f.fraseSecreta = frase.getPassword();
                        f.gid = grupo.getSelectedIndex() == 0 ? Usuario.GID_ADMINISTRADOR : Usuario.GID_USUARIO;
                        f.senha = senha.getPassword();
                        f.confirmacaoSenha = confirmacao.getPassword();
                        cadastrar(f, partida);
                    }
                });
                voltar.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        if (partida) {
                            encerrarExecucao();
                        } else {
                            sistema.voltarDeCadastrar();
                            telaPrincipal();
                        }
                    }
                });

                JPanel form = formulario();
                linha(form, 0, "Caminho do arquivo do certificado digital:", comArquivo(certificado, false));
                linha(form, 1, "Caminho do arquivo da chave privada:", comArquivo(chave, false));
                linha(form, 2, "Frase secreta:", frase);
                linha(form, 3, "Grupo:", grupo);
                linha(form, 4, "Senha pessoal:", senha);
                linha(form, 5, "Confirmação senha pessoal:", confirmacao);

                JPanel corpo2 = new JPanel(new BorderLayout(0, 8));
                corpo2.add(rotulo("Formulário de Cadastro:"), BorderLayout.NORTH);
                JPanel centro = new JPanel(new BorderLayout());
                centro.add(form, BorderLayout.NORTH);
                centro.add(botoes(cadastrar, voltar), BorderLayout.CENTER);
                corpo2.add(centro, BorderLayout.CENTER);

                JComponent topo = partida
                    ? titulo("Partida do sistema: cadastro do administrador do Cofre Digital")
                    : cabecalho(sistema.getUsuarioSessao());
                mostrar(painel(topo, rotulo("Total de usuários do sistema: " + sistema.totalUsuarios()), corpo2),
                        certificado);
            }
        });
    }

    private void cadastrar(final Cadastro.Formulario f, final boolean partida) {
        rodar(new Acao() {
            public void executar() throws Exception {
                Cadastro.Preparacao prep = sistema.prepararCadastro(f);
                if (!prep.ok()) {
                    erro(prep.mensagem);
                    formularioAnterior = f;
                    telaCadastro(partida);
                    return;
                }
                StringBuilder dados = new StringBuilder("Confirme os dados do certificado digital:\n\n");
                for (Map.Entry<String, String> d : prep.dadosCertificado().entrySet()) {
                    dados.append(d.getKey()).append(": ").append(d.getValue()).append('\n');
                }
                int opcao = JOptionPane.showConfirmDialog(CofreDigital.this, area(dados.toString(), 12),
                    "Confirmação de cadastro", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
                if (opcao != JOptionPane.YES_OPTION) {
                    sistema.getCadastro().rejeitar(prep, sistema.getUsuarioSessao());
                    formularioAnterior = f;
                    telaCadastro(partida);
                    return;
                }
                Cadastro.Confirmacao conf = sistema.getCadastro().confirmar(prep, sistema.getUsuarioSessao());
                if (conf.status == Cadastro.StatusConfirmacao.LOGIN_DUPLICADO) {
                    erro("Já existe um usuário cadastrado com este login name (e-mail do certificado).");
                    formularioAnterior = f;
                    telaCadastro(partida);
                    return;
                }
                JOptionPane.showMessageDialog(CofreDigital.this, new Object[] {
                    area("Usuário " + conf.usuario.getLoginName() + " cadastrado com sucesso.\n\n"
                       + "Leia o QRCode com o aplicativo Google Authenticator ou cadastre a chave "
                       + "secreta manualmente (\"Inserir chave de configuração\", baseada no horário):\n\n"
                       + "Chave secreta (BASE32): " + conf.segredoTotpBase32 + "\n\n"
                       + "URI: " + conf.uriOtpAuth + "\n", 11),
                    qrCode(conf.uriOtpAuth)},
                    "Cadastro efetivado", JOptionPane.INFORMATION_MESSAGE);
                if (partida) {
                    // a frase secreta do administrador fica em memoria durante a execucao
                    sistema.definirFraseAdministrador(f.fraseSecreta);
                    f.apagar();
                    iniciarAutenticacao();
                } else {
                    f.apagar();
                    formularioAnterior = null;
                    telaCadastro(false);
                }
            }
        });
    }

    // =====================================================================
    // Tela de Consultar Pasta de Arquivos Secretos do Usuario
    // =====================================================================

    private void telaConsulta() {
        rodar(new Acao() {
            public void executar() throws Exception {
                sistema.telaConsulta();
                listagem = null;
                final Usuario u = sistema.atualizarUsuarioSessao();
                final JLabel totalConsultas = rotulo("Total de consultas do usuário: " + u.getTotalConsultas());
                final JTextField pasta = campo(40, CAMPO_255);
                final JPasswordField frase = new JPasswordField(40);
                limitar(frase, CAMPO_255);
                final DefaultTableModel modelo = new DefaultTableModel(
                        new Object[] {"Nome do arquivo", "Dono", "Grupo", "Acesso"}, 0) {
                    public boolean isCellEditable(int linha, int coluna) {
                        return false;
                    }
                };
                final JTable tabela = new JTable(modelo);
                tabela.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

                JButton listar = new JButton("Listar");
                JButton abrir = new JButton("Decriptar arquivo selecionado");
                JButton voltar = new JButton("Voltar de Consultar para o Menu Principal");

                listar.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        rodar(new Acao() {
                            public void executar() throws Exception {
                                char[] f = frase.getPassword();
                                try {
                                    listagem = sistema.listar(pasta.getText(), f);
                                } finally {
                                    Arrays.fill(f, '\0');
                                }
                                totalConsultas.setText("Total de consultas do usuário: "
                                                     + sistema.getUsuarioSessao().getTotalConsultas());
                                modelo.setRowCount(0);
                                if (!listagem.ok()) {
                                    erro(listagem.mensagem);
                                    return;
                                }
                                for (Consulta.Entrada en : listagem.entradas) {
                                    modelo.addRow(new Object[] {en.nomeSecreto, en.dono, en.grupo, descricao(en)});
                                }
                                if (listagem.avisoShare != null) {
                                    aviso(listagem.avisoShare);
                                }
                                if (listagem.entradas.isEmpty()) {
                                    aviso("Nenhum arquivo da pasta segura pode ser visualizado por este usuário.");
                                }
                            }
                        });
                    }
                });
                final Runnable decriptar = new Runnable() {
                    public void run() {
                        final int linha = tabela.getSelectedRow();
                        if (listagem == null || !listagem.ok() || linha < 0) {
                            aviso("Selecione um arquivo da lista.");
                            return;
                        }
                        rodar(new Acao() {
                            public void executar() throws Exception {
                                Consulta.ResultadoArquivo r = sistema.decriptar(listagem, listagem.entradas.get(linha));
                                if (r.status == Consulta.StatusArquivo.OK) {
                                    JOptionPane.showMessageDialog(CofreDigital.this, r.mensagem, "Cofre Digital",
                                                                  JOptionPane.INFORMATION_MESSAGE);
                                } else {
                                    erro(r.mensagem);
                                }
                            }
                        });
                    }
                };
                abrir.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        decriptar.run();
                    }
                });
                tabela.addMouseListener(new MouseAdapter() {
                    public void mouseClicked(MouseEvent e) {
                        if (e.getClickCount() == 2) {
                            decriptar.run();
                        }
                    }
                });
                voltar.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        sistema.voltarDeConsultar();
                        listagem = null;
                        telaPrincipal();
                    }
                });

                JPanel form = formulario();
                linha(form, 0, "Caminho da pasta:", comArquivo(pasta, true));
                linha(form, 1, "Frase secreta:", frase);

                JPanel corpo2 = new JPanel(new BorderLayout(0, 8));
                JPanel topo = new JPanel(new BorderLayout());
                topo.add(form, BorderLayout.CENTER);
                topo.add(botoes(listar), BorderLayout.SOUTH);
                corpo2.add(topo, BorderLayout.NORTH);
                JScrollPane rolagem = new JScrollPane(tabela);
                rolagem.setPreferredSize(new Dimension(700, 180));
                corpo2.add(rolagem, BorderLayout.CENTER);
                corpo2.add(botoes(abrir, voltar), BorderLayout.SOUTH);

                mostrar(painel(cabecalho(u), totalConsultas, corpo2), pasta);
            }
        });
    }

    private static String descricao(Consulta.Entrada e) {
        switch (e.acesso) {
            case DONO:
                return "Dono";
            case COMPARTILHADO:
                return "Compartilhado (" + e.idCompartilhamento + ")";
            default:
                return "Grupo";
        }
    }

    // =====================================================================
    // Tela de Saida
    // =====================================================================

    private void telaSaida() {
        rodar(new Acao() {
            public void executar() throws Exception {
                sistema.telaSaida();
                Usuario u = sistema.atualizarUsuarioSessao();
                JButton sessao = new JButton("Encerrar Sessão");
                JButton sistemaBotao = new JButton("Encerrar Sistema");
                JButton voltar = new JButton("Voltar de Sair para o Menu Principal");
                sessao.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        sistema.encerrarSessao();
                        telaEtapa1();
                    }
                });
                sistemaBotao.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        sistema.botaoEncerrarSistema();
                        encerrarExecucao();
                    }
                });
                voltar.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        sistema.voltarDeSair();
                        telaPrincipal();
                    }
                });
                JPanel corpo2 = new JPanel();
                corpo2.setLayout(new BoxLayout(corpo2, BoxLayout.Y_AXIS));
                corpo2.add(rotulo("Saída do sistema:"));
                corpo2.add(Box.createVerticalStrut(10));
                corpo2.add(rotulo("Pressione o botão Encerrar Sessão ou o botão Encerrar Sistema para confirmar."));
                corpo2.add(Box.createVerticalStrut(10));
                JPanel b1 = botoes(sessao, sistemaBotao);
                JPanel b2 = botoes(voltar);
                for (JPanel b : new JPanel[] {b1, b2}) {
                    b.setAlignmentX(LEFT_ALIGNMENT);
                    b.setMaximumSize(b.getPreferredSize());
                }
                corpo2.add(b1);
                corpo2.add(b2);
                mostrar(painel(cabecalho(u), rotulo("Total de acessos do usuário: " + u.getTotalAcessos()), corpo2),
                        null);
            }
        });
    }

    // =====================================================================
    // Componentes
    // =====================================================================

    private JComponent cabecalho(Usuario u) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.add(rotulo("Login: " + u.getLoginName()));
        p.add(rotulo("Grupo: " + u.getGrupo()));
        p.add(rotulo("Nome: " + u.getNome()));
        return p;
    }

    //
    // tela dividida em cabecalho, corpo 1 e corpo 2
    private static JPanel painel(JComponent cabecalho, JComponent corpo1, JComponent corpo2) {
        JPanel p = new JPanel(new BorderLayout(0, 12));
        JPanel topo = new JPanel();
        topo.setLayout(new BoxLayout(topo, BoxLayout.Y_AXIS));
        cabecalho.setAlignmentX(LEFT_ALIGNMENT);
        topo.add(cabecalho);
        topo.add(Box.createVerticalStrut(10));
        JSeparator s1 = new JSeparator();
        s1.setAlignmentX(LEFT_ALIGNMENT);
        topo.add(s1);
        topo.add(Box.createVerticalStrut(10));
        corpo1.setAlignmentX(LEFT_ALIGNMENT);
        topo.add(corpo1);
        topo.add(Box.createVerticalStrut(10));
        JSeparator s2 = new JSeparator();
        s2.setAlignmentX(LEFT_ALIGNMENT);
        topo.add(s2);
        p.add(topo, BorderLayout.NORTH);
        p.add(corpo2, BorderLayout.CENTER);
        return p;
    }

    private void mostrar(JComponent tela, final JComponent foco) {
        conteudo.removeAll();
        conteudo.add(tela, BorderLayout.CENTER);
        conteudo.revalidate();
        conteudo.repaint();
        if (foco != null) {
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    foco.requestFocusInWindow();
                }
            });
        }
    }

    private static JLabel titulo(String texto) {
        JLabel l = new JLabel(texto);
        l.setFont(l.getFont().deriveFont(Font.BOLD, 16f));
        return l;
    }

    private static JLabel rotulo(String texto) {
        JLabel l = new JLabel(texto);
        l.setAlignmentX(LEFT_ALIGNMENT);
        return l;
    }

    private static JPanel formulario() {
        return new JPanel(new GridBagLayout());
    }

    private static void linha(JPanel form, int y, String rotulo, JComponent campo) {
        GridBagConstraints g = new GridBagConstraints();
        g.gridx = 0;
        g.gridy = y;
        g.anchor = GridBagConstraints.WEST;
        g.insets = new Insets(4, 0, 4, 12);
        form.add(new JLabel(rotulo), g);
        g.gridx = 1;
        g.weightx = 1;
        g.fill = GridBagConstraints.HORIZONTAL;
        form.add(campo, g);
    }

    private static JPanel botoes(JButton... botoes) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 8));
        for (JButton b : botoes) {
            p.add(b);
            p.add(Box.createHorizontalStrut(8));
        }
        return p;
    }

    private static JButton botaoMenu(String texto, final Runnable acao) {
        JButton b = new JButton(texto);
        b.setAlignmentX(LEFT_ALIGNMENT);
        b.setHorizontalAlignment(SwingConstants.LEFT);
        b.setMaximumSize(new Dimension(460, 36));
        b.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                acao.run();
            }
        });
        return b;
    }

    private static JTextField campo(int colunas, int limite) {
        JTextField f = new JTextField(colunas);
        limitar(f, limite);
        return f;
    }

    //
    // limita a quantidade de caracteres de um campo
    private static void limitar(JTextComponent campo, final int limite) {
        ((AbstractDocument) campo.getDocument()).setDocumentFilter(new DocumentFilter() {
            public void insertString(FilterBypass fb, int pos, String texto, AttributeSet a) throws BadLocationException {
                replace(fb, pos, 0, texto, a);
            }

            public void replace(FilterBypass fb, int pos, int tamanho, String texto, AttributeSet a)
                    throws BadLocationException {
                int novo = fb.getDocument().getLength() - tamanho + (texto == null ? 0 : texto.length());
                if (novo <= limite) {
                    super.replace(fb, pos, tamanho, texto, a);
                } else {
                    Toolkit.getDefaultToolkit().beep();
                }
            }
        });
    }

    //
    // campo de caminho com botao para escolher o arquivo ou a pasta
    private JComponent comArquivo(final JTextField campo, final boolean pasta) {
        JPanel p = new JPanel(new BorderLayout(6, 0));
        p.add(campo, BorderLayout.CENTER);
        JButton escolher = new JButton("...");
        escolher.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                JFileChooser chooser = new JFileChooser(campo.getText().isEmpty() ? "." : campo.getText());
                chooser.setFileSelectionMode(pasta ? JFileChooser.DIRECTORIES_ONLY : JFileChooser.FILES_ONLY);
                if (chooser.showOpenDialog(CofreDigital.this) == JFileChooser.APPROVE_OPTION) {
                    String caminho = chooser.getSelectedFile().getPath();
                    campo.setText(caminho.length() <= CAMPO_255 ? caminho : caminho.substring(0, CAMPO_255));
                }
            }
        });
        p.add(escolher, BorderLayout.EAST);
        return p;
    }

    //
    // QRCode da URI otpauth para o Google Authenticator (se falhar, fica so a chave em texto)
    private static JComponent qrCode(String uri) {
        try {
            JLabel qr = new JLabel(new ImageIcon(QRCodeOtp.gerar(uri, 260)));
            qr.setHorizontalAlignment(SwingConstants.CENTER);
            return qr;
        } catch (Exception e) {
            return new JLabel("Não foi possível gerar o QRCode: " + e.getMessage());
        }
    }

    private static JComponent area(String texto, int linhas) {
        JTextArea a = new JTextArea(texto, linhas, 60);
        a.setEditable(false);
        a.setLineWrap(true);
        a.setWrapStyleWord(true);
        return new JScrollPane(a);
    }

    private static void habilitar(List<JButton> botoes, boolean habilitado) {
        for (JButton b : botoes) {
            b.setEnabled(habilitado);
        }
    }

    private void aviso(String mensagem) {
        JOptionPane.showMessageDialog(this, mensagem, "Cofre Digital", JOptionPane.WARNING_MESSAGE);
    }

    private void erro(String mensagem) {
        JOptionPane.showMessageDialog(this, mensagem, "Cofre Digital", JOptionPane.ERROR_MESSAGE);
    }

    private interface Acao {
        void executar() throws Exception;
    }

    private void rodar(Acao acao) {
        try {
            acao.executar();
        } catch (Exception e) {
            erro("Erro: " + e.getMessage());
        }
    }
}
