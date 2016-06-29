import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;

public class ChoiceWindow extends AppWindow{
    private JButton btnLogin;
    private JButton btnRegistrieren;

    public ChoiceWindow(){
        super();
        //Layout Elemente
        GridBagLayout gridBagLayout = new GridBagLayout();
        gridBagLayout.columnWidths = new int[]{90, 253, 0};
        gridBagLayout.rowHeights = new int[]{60, 16, 0, 0, 0, 0, 0};
        gridBagLayout.columnWeights = new double[]{0.0, 0.0, Double.MIN_VALUE};
        gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
        getContentPane().setLayout(gridBagLayout);

        JLabel lblNewLabel = new JLabel("Willkommen im Chat-Client von Team 3");
        GridBagConstraints gbc_lblNewLabel = new GridBagConstraints();
        gbc_lblNewLabel.insets = new Insets(0, 0, 5, 0);
        gbc_lblNewLabel.anchor = GridBagConstraints.EAST;
        gbc_lblNewLabel.gridx = 1;
        gbc_lblNewLabel.gridy = 1;
        getContentPane().add(lblNewLabel, gbc_lblNewLabel);

        btnLogin = new JButton("Login");
        GridBagConstraints gbc_btnLogin = new GridBagConstraints();
        gbc_btnLogin.insets = new Insets(0, 0, 5, 0);
        gbc_btnLogin.gridx = 1;
        gbc_btnLogin.gridy = 4;
        getContentPane().add(btnLogin, gbc_btnLogin);

        btnRegistrieren = new JButton("Registrieren");
        GridBagConstraints gbc_btnRegistrieren = new GridBagConstraints();
        gbc_btnRegistrieren.gridx = 1;
        gbc_btnRegistrieren.gridy = 5;
        getContentPane().add(btnRegistrieren, gbc_btnRegistrieren);

        initButtons();
        this.setVisible(true);
    }


    //Den Buttons werden click-Events hinzugefügt.
    public void initButtons(){

        btnLogin.addActionListener(new NewFrameActionListener(this) {
            @Override
            public void actionPerformed(ActionEvent e) {
                this.dispose();
                new LoginWindow();
            }
        });

        btnRegistrieren.addActionListener(new NewFrameActionListener(this) {
            @Override
            public void actionPerformed(ActionEvent e) {
                this.dispose();
                new RegisterWindow();
            }
        });
    }
}
