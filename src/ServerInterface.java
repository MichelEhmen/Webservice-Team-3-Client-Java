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
    String id;
    String pubKey;
    String privateKey;

    public boolean login(String id, String password) throws Exception {
        //Fertig
        JSONObject json = getUser(id);

        String salt = json.getString("saltmaster");
        String pubKey = json.getString("pubkey"); //Nur für den Nachrichtenversandt
        String privKeyEnc = json.getString("privkeyenc");

        String masterKey = c.generateMasterkey(password, salt);

        try {
            privateKey = c.decryptPrivateKey(privKeyEnc, masterKey);
        }catch(Exception e){
            return false;
        }
        this.id = id;
        return true;
    }

    public int register(String id, String password) throws Exception {
        //Fertig

        URL url = new URL("http://127.0.0.1:3000/" + id);
        HttpURLConnection httpCon = (HttpURLConnection) url.openConnection();
        httpCon.setDoOutput(true);
        httpCon.setRequestMethod("POST");

        c.generateKeyPair();
        String privateKey = c.getPrivateKeyString();
        String saltmaster = c.generateSaltmaster();
        String masterKey = c.generateMasterkey(password, saltmaster);
        String publicKey = c.getPublicKeyString();

        Map<String,Object> params = new LinkedHashMap<>();
        params.put("saltMaster", saltmaster);
        params.put("privKeyEnc", c.encryptPrivateKey(privateKey, masterKey));
        params.put("pubKey", publicKey);

        StringBuilder postData = generatePostData(params);
        byte[] postDataBytes = postData.toString().getBytes();

        httpCon.getOutputStream().write(postDataBytes);
        int returnCode = httpCon.getResponseCode();
        httpCon.disconnect();
        return returnCode;
    }

    public int sendMessage(String targetID, String message) throws Exception {

        JSONObject recipient = getUser(targetID);
        String pubKeyRecipient = recipient.getString("pubKey");

        URL url = new URL("http://127.0.0.1:3000/" + id +"/message");
        HttpURLConnection httpCon = (HttpURLConnection) url.openConnection();
        httpCon.setDoOutput(true);
        httpCon.setRequestMethod("POST");

        String keyRecipient = c.generateKeyRecipient();
        String iv = c.generateIv();
        String cipher = c.encryptMessage(message, keyRecipient, iv);
        String keyRecipientEnc = c.encryptKeyRecipient(keyRecipient, pubKeyRecipient);

        String sigRecipient = c.hashSigRecipient(privateKey, id, cipher, iv, keyRecipient);
        JSONObject innerEnvelope = new JSONObject();
        innerEnvelope.put("userID", id);
        innerEnvelope.put("cipher", cipher);
        innerEnvelope.put("iv", iv);
        innerEnvelope.put("keyRecEnc", keyRecipientEnc);
        innerEnvelope.put("sigRecipient", sigRecipient);
        long timestamp = System.currentTimeMillis()/1000L;

        String sigService = c.hashSigService(privateKey, targetID, timestamp, innerEnvelope);

        Map<String,Object> params = new LinkedHashMap<>();
        params.put("userID", id);
        params.put("cipher", cipher);
        params.put("iv", iv);
        params.put("keyRecEnc", keyRecipientEnc);
        params.put("sigRecipient", sigRecipient);
        params.put("timeStamp", timestamp);
        params.put("targetID", targetID);
        params.put("sigService", sigService);

        StringBuilder postData = generatePostData(params);
        byte[] postDataBytes = postData.toString().getBytes();

        httpCon.getOutputStream().write(postDataBytes);
        int returnCode = httpCon.getResponseCode();
        httpCon.disconnect();
        return returnCode;
    }

    public String[] receiveMessages() throws Exception{
//        StringBuilder result = new StringBuilder();
//        URL url = new URL("http://127.0.0.1:3000/" + id + "message");
//        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
//        conn.setRequestMethod("GET");
//        //Paremeter übergeben timestamp sigService
//
//        BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
//        String line;
//        while ((line = rd.readLine()) != null) {
//            result.append(line);
//        }
//        rd.close();
//        JSONObject json = new JSONObject(result.toString());
//        //JSON prüfen und zum Array wandeln
        String[] messages = new String[12];
        messages[0]= "Hallo wie geht es dir?";
        messages[1]= "Selfies post-ironic art party food truck chartreuse. Next level mlkshk keffiyeh locavore etsy.";
        messages[2]= "I'm number ONE";
        messages[3]= "Wenn du kein iPhone hast, hast du kein iPhone!";
        messages[4]= "Hallo wie geht es dir?";
        messages[5]= "Selfies post-ironic art party food truck chartreuse. Next level mlkshk keffiyeh locavore etsy.";
        messages[6]= "I'm number ONE";
        messages[7]= "Wenn du kein iPhone hast, hast du kein iPhone!";
        messages[8]= "Hallo wie geht es dir?";
        messages[9]= "Selfies post-ironic art party food truck chartreuse. Next level mlkshk keffiyeh locavore etsy.";
        messages[10]= "I'm number ONE";
        messages[11]= "Wenn du kein iPhone hast, hast du kein iPhone!";
        return messages;
    }

    public JSONObject getUser(String id) throws Exception{
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
        return json;
    }

    public StringBuilder generatePostData(Map<String,Object> params) throws Exception{
        StringBuilder postData = new StringBuilder();
        for (Map.Entry<String,Object> param : params.entrySet()) {
            if (postData.length() != 0) postData.append('&');
            postData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
            postData.append('=');
            postData.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
        }
        return  postData;
    }
}
