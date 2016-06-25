import javax.swing.*;
import java.awt.*;

/**
 * Created by michelehmen on 25.06.16.
 */
public class MessageWindow extends AppWindow {
    ServerInterface server;
    JLabel lblJson;


    public MessageWindow(String userID){
        super();
        server = new ServerInterface();

        GridBagLayout gridBagLayout = new GridBagLayout();
        gridBagLayout.columnWidths = new int[]{0, 0, 0, 0};
        gridBagLayout.rowHeights = new int[]{0, 0, 0, 0};
        gridBagLayout.columnWeights = new double[]{0.0, 0.0, 1.0, Double.MIN_VALUE};
        gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, Double.MIN_VALUE};
        getContentPane().setLayout(gridBagLayout);

        JLabel lblJsonString = new JLabel("JSon String:");
        GridBagConstraints gbc_lblJsonString = new GridBagConstraints();
        gbc_lblJsonString.insets = new Insets(0, 0, 0, 5);
        gbc_lblJsonString.gridx = 1;
        gbc_lblJsonString.gridy = 2;
        getContentPane().add(lblJsonString, gbc_lblJsonString);

        lblJson = new JLabel("");
        GridBagConstraints gbc_lblJson = new GridBagConstraints();
        gbc_lblJson.gridx = 2;
        gbc_lblJson.gridy = 2;
        getContentPane().add(lblJson, gbc_lblJson);

        getJson(userID);
        this.setVisible(true);
    }
    public void getJson(String id){
        try {
            lblJson.setText(server.getUser(id));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
