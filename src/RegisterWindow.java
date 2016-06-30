import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;

public class RegisterWindow extends AppWindow {
    private JTextField fldUserId;
    private JPasswordField fldPassword;
    private JButton btnRegister;
    private ServerInterface server;
    private JButton btnZurck;

    public RegisterWindow() {
        super();
        server = new ServerInterface();

        GridBagLayout gridBagLayout = new GridBagLayout();
        gridBagLayout.columnWidths = new int[]{0, 0, 0, 0, 0, 0};
        gridBagLayout.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0};
        gridBagLayout.columnWeights = new double[]{0.0, 0.0, 0.0, 1.0, 1.0, Double.MIN_VALUE};
        gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
        getContentPane().setLayout(gridBagLayout);

        btnZurck = new JButton("Zurück");
        GridBagConstraints gbc_btnZurck = new GridBagConstraints();
        gbc_btnZurck.insets = new Insets(0, 0, 5, 5);
        gbc_btnZurck.gridx = 0;
        gbc_btnZurck.gridy = 0;
        getContentPane().add(btnZurck, gbc_btnZurck);

        JLabel lblBitteGebenSie = new JLabel("Bitte geben Sie ihre Daten ein");
        GridBagConstraints gbc_lblBitteGebenSie = new GridBagConstraints();
        gbc_lblBitteGebenSie.insets = new Insets(0, 0, 5, 5);
        gbc_lblBitteGebenSie.gridx = 3;
        gbc_lblBitteGebenSie.gridy = 2;
        getContentPane().add(lblBitteGebenSie, gbc_lblBitteGebenSie);

        JLabel lblUserid = new JLabel("User-ID:");
        GridBagConstraints gbc_lblUserid = new GridBagConstraints();
        gbc_lblUserid.anchor = GridBagConstraints.EAST;
        gbc_lblUserid.insets = new Insets(0, 0, 5, 5);
        gbc_lblUserid.gridx = 1;
        gbc_lblUserid.gridy = 3;
        getContentPane().add(lblUserid, gbc_lblUserid);

        fldUserId = new JTextField();
        GridBagConstraints gbc_fldUserId = new GridBagConstraints();
        gbc_fldUserId.insets = new Insets(0, 0, 5, 5);
        gbc_fldUserId.fill = GridBagConstraints.HORIZONTAL;
        gbc_fldUserId.gridx = 3;
        gbc_fldUserId.gridy = 3;
        getContentPane().add(fldUserId, gbc_fldUserId);
        fldUserId.setColumns(10);

        JLabel lblPasswort = new JLabel("Passwort:");
        GridBagConstraints gbc_lblPasswort = new GridBagConstraints();
        gbc_lblPasswort.insets = new Insets(0, 0, 5, 5);
        gbc_lblPasswort.gridx = 1;
        gbc_lblPasswort.gridy = 5;
        getContentPane().add(lblPasswort, gbc_lblPasswort);

        fldPassword = new JPasswordField();
        GridBagConstraints gbc_fldPassword = new GridBagConstraints();
        gbc_fldPassword.insets = new Insets(0, 0, 5, 5);
        gbc_fldPassword.fill = GridBagConstraints.HORIZONTAL;
        gbc_fldPassword.gridx = 3;
        gbc_fldPassword.gridy = 5;
        getContentPane().add(fldPassword, gbc_fldPassword);

        btnRegister = new JButton("Registrieren");
        GridBagConstraints gbc_btnRegister = new GridBagConstraints();
        gbc_btnRegister.insets = new Insets(0, 0, 0, 5);
        gbc_btnRegister.gridx = 3;
        gbc_btnRegister.gridy = 7;
        getContentPane().add(btnRegister, gbc_btnRegister);

        initButtons();
        this.setVisible(true);
    }

    public void initButtons() {
        btnRegister.addActionListener(new NewFrameActionListener(this) {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    if (server.register(fldUserId.getText(), String.valueOf(fldPassword.getPassword()))) {
                        JOptionPane.showMessageDialog(null, "Die Registrierung war erfolgreich");
                    } else {
                        JOptionPane.showMessageDialog(null, "Die Registrierung war nicht erfolgreich");
                    }
                } catch (Exception e1) {
                    e1.printStackTrace();
                }
            }
        });

        btnZurck.addActionListener(new NewFrameActionListener(this) {
            @Override
            public void actionPerformed(ActionEvent e) {
                this.dispose();
                new ChoiceWindow();
            }
        });
    }
}