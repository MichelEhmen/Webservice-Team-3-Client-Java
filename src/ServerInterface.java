import java.net.*;
import java.io.*;
import org.json.*;

/**
 * Created by michelehmen on 25.06.16.
 */
public class ServerInterface {
    public String getUser(String id) throws Exception {
        StringBuilder result = new StringBuilder();
        URL url = new URL("http://127.0.0.1:3000/"+id);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String line;
        while ((line = rd.readLine()) != null) {
            result.append(line);
        }
        rd.close();
        JSONObject json = new JSONObject(result.toString());
        System.out.println(json);
        String salt = json.getString("saltmaster");
        return salt;
    }
}
