/**
 * Created by michelehmen on 26.06.16.
 */
public class Message {
    public String id;
    public String message;

    public Message(String id, String message){
        this.message = message;
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public String getMessage() {
        return message;
    }
}
