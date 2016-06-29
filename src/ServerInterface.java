import java.net.*;
import java.io.*;
import org.json.*;


public class ServerInterface {
    private Crypt c = new Crypt();
    private String id;
    private String privateKey;

    public boolean login(String id, String password) throws Exception {
        JSONObject json = getUser(id);

        String salt = json.getString("saltmaster");
        String pubKey = json.getString("pubkey"); //Nur für den Nachrichtenversandt.
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

    public int register(String id, String password)throws Exception{
        URL url = new URL("http://127.0.0.1:3000/" + id);
        HttpURLConnection httpCon = (HttpURLConnection) url.openConnection();
        httpCon.setDoOutput(true);
        httpCon.setRequestMethod("POST");
        httpCon.setRequestProperty("Content-Type", "application/json");
        httpCon.setRequestProperty("Accept", "application/json");

        c.generateKeyPair();
        String privateKey = c.getPrivateKey();
        String saltmaster = c.generateSaltmaster();
        String masterKey = c.generateMasterkey(password, saltmaster);
        String publicKey = c.getPublicKey();

        JSONObject user = new JSONObject();
        user.put("saltMaster", saltmaster);
        user.put("privKeyEnc", c.encryptPrivateKey(privateKey, masterKey));
        user.put("pubKey", publicKey);
        OutputStreamWriter wr = new OutputStreamWriter(httpCon.getOutputStream());
        wr.write(user.toString());
        wr.flush();
        int returnCode = httpCon.getResponseCode();
        httpCon.disconnect();
        return returnCode;
    }

    public int sendMessage(String id, String targetID, String message, String privKey) throws Exception {
        //fertig
        JSONObject recipient = getUser(targetID);
        String pubKeyRecipient = recipient.getString("pubkey");

        URL url = new URL("http://127.0.0.1:3000/" + id +"/message");
        HttpURLConnection httpCon = (HttpURLConnection) url.openConnection();
        httpCon.setDoOutput(true);
        httpCon.setRequestMethod("POST");
        httpCon.setRequestProperty("Content-Type", "application/json");
        httpCon.setRequestProperty("Accept", "application/json");

        long timestamp = System.currentTimeMillis()/1000L;
        String keyRecipient = c.generateKeyRecipient();
        String iv = c.generateIv();
        String cipher = c.encryptMessage(message, keyRecipient, iv);
        String keyRecipientEnc = c.encryptKeyRecipient(keyRecipient, pubKeyRecipient);
        String sigRecipient = c.hashAndEncryptSigRecipient(id, cipher, iv, keyRecipient, privKey);

        JSONObject innerEnvelope = new JSONObject();
        innerEnvelope.put("sourceUserID", id);
        innerEnvelope.put("cipher", cipher);
        innerEnvelope.put("iv", iv);
        innerEnvelope.put("keyRecEnc", keyRecipientEnc);
        innerEnvelope.put("sigRec", sigRecipient);



        String sigService = c.hashAndEncryptSigService(targetID, timestamp, innerEnvelope, privKey);

//        String mockCipher = message;
//        String mockKeyRecipientEnc = "324232342";
//        String mockSigRec = "0287548243";
//        String mockSigService = "2zd203d";

        JSONObject messageJs = new JSONObject();
        messageJs.put("targetUserID", targetID);
        messageJs.put("cipher", cipher);
        messageJs.put("iv", iv);
        messageJs.put("keyRecEnc", keyRecipientEnc);
        messageJs.put("sigRec", sigRecipient);
        messageJs.put("sigService", sigService);
        messageJs.put("timestamp", timestamp);

        OutputStreamWriter wr = new OutputStreamWriter(httpCon.getOutputStream());
        wr.write(messageJs.toString());
        wr.flush();
        int returnCode = httpCon.getResponseCode();
        httpCon.disconnect();
        return returnCode;
    }

    public String[] receiveMessages(String id, String privKey) throws Exception{
        StringBuilder result = new StringBuilder();
        URL url = new URL("http://127.0.0.1:3000/" + id + "/messages");
        HttpURLConnection httpCon = (HttpURLConnection) url.openConnection();
        httpCon.setDoOutput(true);
        httpCon.setRequestMethod("POST");
        httpCon.setRequestProperty("Content-Type", "application/json");
        httpCon.setRequestProperty("Accept", "application/json");

        long timestamp = System.currentTimeMillis()/1000L;
        String sigService = c.hashAndEncryptIdTime(id, timestamp, privKey);
//
//      Anfrage zum Nachrichtenabruf
        JSONObject messageRequest = new JSONObject();
        messageRequest.put("timeStamp", timestamp);
        messageRequest.put("sigService", sigService);
        OutputStreamWriter wr = new OutputStreamWriter(httpCon.getOutputStream());
        wr.write(messageRequest.toString());
        wr.flush();

        int HttpResult = httpCon.getResponseCode();
        if (HttpResult == HttpURLConnection.HTTP_OK) {
        //Nachrichten werden vom Server abgerufen
            BufferedReader rd = new BufferedReader(new InputStreamReader(httpCon.getInputStream()));
            String line;
            while ((line = rd.readLine()) != null) {
                result.append(line);
            }
            rd.close();
            System.out.println("" + result.toString());
        } else {
            System.out.println(httpCon.getResponseMessage());
        }

        JSONArray jsonArr = new JSONArray(result.toString());
        String[] messages = new String[jsonArr.length()*3];
        int jlistIndex = 0;
        for(int i=0; i<jsonArr.length(); i++){
            JSONObject jsonObj = jsonArr.getJSONObject(i);
            String sigRec = jsonObj.getString("sigrec");
            int fromID = jsonObj.getInt("sourceuserid");
            JSONObject user = getUser(String.valueOf(fromID));
            String pubKeySource = user.getString("pubkey");
            try{
                c.decryptSigRecipient(sigRec, pubKeySource);
                String iv = jsonObj.getString("iv");
                String cipher = jsonObj.getString("cipher");
                String keyRecEnc = jsonObj.getString("keyrecenc");
                String keyRec = c.decryptKeyRecipient(keyRecEnc,privKey);
                messages[jlistIndex] = "Absender:" +fromID;
                jlistIndex++;
                messages[jlistIndex] = c.decryptMessage(cipher, keyRec, iv);
                jlistIndex++;
                messages[jlistIndex] = " ";
                jlistIndex++;
            }catch (Exception e){
                messages[jlistIndex] = "[verfälschte Nachricht!]";
                jlistIndex++;
                messages[jlistIndex] = " ";
                jlistIndex++;
            }

        };
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

    public String getPrivateKey(){
        return privateKey;
    }
}
