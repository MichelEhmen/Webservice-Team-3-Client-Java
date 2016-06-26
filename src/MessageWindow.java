import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;

/**
 * Created by michelehmen on 25.06.16.
 */
public class MessageWindow extends AppWindow {
    ServerInterface server;
    JLabel lblJson;
    JButton btnAbsenden;
    JButton btnAusloggen;
    private JTextField fldRecipientId;
    private JTextField textField;


    public MessageWindow(String userID){
        super();
        server = new ServerInterface();

        GridBagLayout gridBagLayout = new GridBagLayout();
        gridBagLayout.columnWidths = new int[]{0, 0, 0, 0};
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

        JScrollPane scrollPane = new JScrollPane();
        GridBagConstraints gbc_scrollPane = new GridBagConstraints();
        gbc_scrollPane.gridheight = 2;
        gbc_scrollPane.gridwidth = 2;
        gbc_scrollPane.fill = GridBagConstraints.BOTH;
        gbc_scrollPane.gridx = 1;
        gbc_scrollPane.gridy = 3;
        getContentPane().add(scrollPane, gbc_scrollPane);

//        getJson(userID);
        initButtons();
        this.setVisible(true);
    }
    public void initButtons(){
        btnAusloggen.addActionListener(new NewFrameActionListener(this) {
            @Override
            public void actionPerformed(ActionEvent e) {
                dispose();
                new LoginWindow();
            }
        });
    }
    public void getJson(String id){
        try {
            lblJson.setText(server.login(id, "test")+"");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
