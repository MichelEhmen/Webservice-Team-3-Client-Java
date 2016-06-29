import javax.swing.*;

public class AppWindow extends JFrame {

    public AppWindow() {
        initApplication();
    }

    public void initApplication(){
        //Default Werte für die JFrame Elemente
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        this.setSize(450, 300);
        this.setTitle("WebService-Team-3-Client");
        this.setLocationRelativeTo(null);
    }
}
