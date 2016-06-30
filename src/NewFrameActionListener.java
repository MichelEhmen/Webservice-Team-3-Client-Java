import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * Created by michelehmen on 25.06.16.
 */
public class NewFrameActionListener implements ActionListener{

    private JFrame frame;
    NewFrameActionListener(JFrame oldframe){
        frame = oldframe;
    }
    @Override
    public void actionPerformed(ActionEvent e) {

    }

    public void dispose(){
        frame.dispose();
    }
}
