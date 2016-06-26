import java.net.*;
import java.io.*;
import java.util.LinkedHashMap;
import java.util.Map;

import org.json.*;

/**
 * Created by michelehmen on 25.06.16.
 */
public class ServerInterface {
    Crypt c = new Crypt();

    public boolean login(String id, String passwort) throws Exception {
        StringBuilder result = new StringBuilder();
        URL url = new URL("http://127.0.0.1:3000/" + id);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String line;
        while ((line = rd.readLine()) != null) {
            result.append(line);
        }
        rd.close();
        JSONObject json = new JSONObject(result.toString());

        String salt = json.getString("saltmaster");
        String pubKey = json.getString("pubkey");
        String privKeyEnc = json.getString("privkeyenc");


//        System.out.println(json);
//        String salt = json.getString("saltmaster");
        return false;
    }

    public int register(String id, String passwort) throws Exception {

        URL url = new URL("http://127.0.0.1:3000/" + id);
        HttpURLConnection httpCon = (HttpURLConnection) url.openConnection();
        httpCon.setDoOutput(true);
        httpCon.setRequestMethod("POST");

        c.generateKeyPair();
        String privateKey = c.getPrivateKeyString();
        byte[] salt = c.generateSalt();
        String masterKey = c.generateMasterkey(passwort, salt);
        String publicKey = c.getPublicKeyString();

        Map<String,Object> params = new LinkedHashMap<>();
        params.put("saltMaster", salt);
        params.put("privKeyEnc", c.encryptPrivateKey(privateKey, masterKey));
        params.put("pubKey", publicKey);

        StringBuilder postData = new StringBuilder();
        for (Map.Entry<String,Object> param : params.entrySet()) {
            if (postData.length() != 0) postData.append('&');
            postData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
            postData.append('=');
            postData.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
        }
        byte[] postDataBytes = postData.toString().getBytes();

        httpCon.getOutputStream().write(postDataBytes);
        int returnCode = httpCon.getResponseCode();
        httpCon.disconnect();
        return returnCode;
    }
}
