import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;


public class MessageWindow extends AppWindow {
    private ServerInterface server;
    private JButton btnAbsenden;
    private JButton btnAusloggen;
    private JButton btnAktualisieren;
    private JTextField fldRecipientId;
    private JTextField textField;
    private String userID;
    private JList<String> messages;
    private JScrollPane scrollPane;
    private GridBagConstraints gbc_scrollPane;


    public MessageWindow(String userID) throws Exception {
        super();
        server = new ServerInterface();
        this.userID = userID;

        GridBagLayout gridBagLayout = new GridBagLayout();
        gridBagLayout.columnWidths = new int[]{0, 104, 236, 0};
        gridBagLayout.rowHeights = new int[]{0, 0, 0, 0, 90, 0};
        gridBagLayout.columnWeights = new double[]{0.0, 1.0, 1.0, Double.MIN_VALUE};
        gridBagLayout.rowWeights = new double[]{0.0, 1.0, 0.0, 0.0, 1.0, Double.MIN_VALUE};
        getContentPane().setLayout(gridBagLayout);

        btnAusloggen = new JButton("Ausloggen");
        GridBagConstraints gbc_btnAusloggen = new GridBagConstraints();
        gbc_btnAusloggen.insets = new Insets(0, 0, 5, 5);
        gbc_btnAusloggen.gridx = 0;
        gbc_btnAusloggen.gridy = 0;
        getContentPane().add(btnAusloggen, gbc_btnAusloggen);

        JLabel lblRecipientId = new JLabel("Recipient ID:");
        GridBagConstraints gbc_lblRecipientId = new GridBagConstraints();
        gbc_lblRecipientId.anchor = GridBagConstraints.EAST;
        gbc_lblRecipientId.insets = new Insets(0, 0, 5, 5);
        gbc_lblRecipientId.gridx = 1;
        gbc_lblRecipientId.gridy = 0;
        getContentPane().add(lblRecipientId, gbc_lblRecipientId);

        fldRecipientId = new JTextField();
        GridBagConstraints gbc_fldRecipientId = new GridBagConstraints();
        gbc_fldRecipientId.insets = new Insets(0, 0, 5, 0);
        gbc_fldRecipientId.fill = GridBagConstraints.HORIZONTAL;
        gbc_fldRecipientId.gridx = 2;
        gbc_fldRecipientId.gridy = 0;
        getContentPane().add(fldRecipientId, gbc_fldRecipientId);
        fldRecipientId.setColumns(10);

        JLabel lblEingeloggtMitId = new JLabel("Eingeloggt mit ID:");
        GridBagConstraints gbc_lblEingeloggtMitId = new GridBagConstraints();
        gbc_lblEingeloggtMitId.anchor = GridBagConstraints.SOUTH;
        gbc_lblEingeloggtMitId.insets = new Insets(0, 0, 5, 5);
        gbc_lblEingeloggtMitId.gridx = 0;
        gbc_lblEingeloggtMitId.gridy = 1;
        getContentPane().add(lblEingeloggtMitId, gbc_lblEingeloggtMitId);

        JLabel lblNachricht = new JLabel("Nachricht:");
        GridBagConstraints gbc_lblNachricht = new GridBagConstraints();
        gbc_lblNachricht.anchor = GridBagConstraints.EAST;
        gbc_lblNachricht.insets = new Insets(0, 0, 5, 5);
        gbc_lblNachricht.gridx = 1;
        gbc_lblNachricht.gridy = 1;
        getContentPane().add(lblNachricht, gbc_lblNachricht);

        textField = new JTextField();
        GridBagConstraints gbc_textField = new GridBagConstraints();
        gbc_textField.insets = new Insets(0, 0, 5, 0);
        gbc_textField.fill = GridBagConstraints.BOTH;
        gbc_textField.gridx = 2;
        gbc_textField.gridy = 1;
        getContentPane().add(textField, gbc_textField);
        textField.setColumns(10);

        JLabel lblId = new JLabel(userID);
        GridBagConstraints gbc_lblId = new GridBagConstraints();
        gbc_lblId.insets = new Insets(0, 0, 5, 5);
        gbc_lblId.gridx = 0;
        gbc_lblId.gridy = 2;
        getContentPane().add(lblId, gbc_lblId);

        btnAktualisieren = new JButton("Aktualisieren");
        GridBagConstraints gbc_btnAktualisieren = new GridBagConstraints();
        gbc_btnAktualisieren.anchor = GridBagConstraints.SOUTHWEST;
        gbc_btnAktualisieren.insets = new Insets(0, 0, 5, 5);
        gbc_btnAktualisieren.gridx = 1;
        gbc_btnAktualisieren.gridy = 2;
        getContentPane().add(btnAktualisieren, gbc_btnAktualisieren);

        btnAbsenden = new JButton("Absenden");
        GridBagConstraints gbc_btnAbsenden = new GridBagConstraints();
        gbc_btnAbsenden.insets = new Insets(0, 0, 5, 0);
        gbc_btnAbsenden.gridx = 2;
        gbc_btnAbsenden.gridy = 2;
        getContentPane().add(btnAbsenden, gbc_btnAbsenden);

        JLabel lblPosteingang = new JLabel("Posteingang:");
        GridBagConstraints gbc_lblPosteingang = new GridBagConstraints();
        gbc_lblPosteingang.insets = new Insets(0, 0, 5, 5);
        gbc_lblPosteingang.gridx = 0;
        gbc_lblPosteingang.gridy = 3;
        getContentPane().add(lblPosteingang, gbc_lblPosteingang);

        messages = new JList(server.receiveMessages(userID));
        scrollPane = new JScrollPane(messages);
        gbc_scrollPane = new GridBagConstraints();
        gbc_scrollPane.gridheight = 2;
        gbc_scrollPane.gridwidth = 2;
        gbc_scrollPane.fill = GridBagConstraints.BOTH;
        gbc_scrollPane.gridx = 1;
        gbc_scrollPane.gridy = 3;
        getContentPane().add(scrollPane, gbc_scrollPane);

        initButtons();
        this.setVisible(true);
    }

    public void initButtons() {
        btnAusloggen.addActionListener(new NewFrameActionListener(this) {
            @Override
            public void actionPerformed(ActionEvent e) {
                server.logout();
                dispose();
                new LoginWindow();
            }
        });
        btnAbsenden.addActionListener(new NewFrameActionListener(this) {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    if (server.sendMessage(userID, fldRecipientId.getText(), textField.getText())) {
                        JOptionPane.showMessageDialog(null, "Die Nachricht wurde abgeschickt.");
                    } else {
                        JOptionPane.showMessageDialog(null, "Die Nachricht konnte nicht abgeschickt werden.");
                    }
                } catch (Exception e1) {
                    e1.printStackTrace();
                }
            }
        });
        btnAktualisieren.addActionListener(new NewFrameActionListener(this) {
            @Override
            public void actionPerformed(ActionEvent e) {

                getContentPane().remove(scrollPane);
                try {
                    messages = new JList(server.receiveMessages(userID));
                } catch (Exception e1) {
                    e1.printStackTrace();
                }
                scrollPane = new JScrollPane(messages);
                getContentPane().add(scrollPane, gbc_scrollPane);
                getContentPane().revalidate();
                getContentPane().repaint();
            }
        });
    }
}
