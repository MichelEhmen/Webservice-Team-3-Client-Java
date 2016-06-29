import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;


public class AppWindow extends JFrame {

    public AppWindow() {
        initApplication();
    }

    public void initApplication(){
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        this.setSize(450, 300);
        this.setTitle("WebService-Team-3-Client");
        this.setLocationRelativeTo(null);
    }
}
