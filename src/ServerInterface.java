import java.net.*;
import java.io.*;
import org.json.*;


public class ServerInterface {
    private Crypt c = new Crypt();
    private String id;
    private static String privateKey;
    private final String address = "http://localhost:3000/";

    /**
     * Die Anwendung bezieht saltmaster, pubkey und privKeyEnc von dem Dienstanbeiter auf Basis der angegebenen Identität.
     * Die Anwendung bildet masterkey mithilfe der PBKDF2 Funktion mit folgenden Parametern:
     * <ul>
     *     <li>Algorithmus: sha-256 </li>
     *     <li>Passwort: password</li>
     *     <li>Salt: salt </li>
     *     <li>Länge: 256 Bit</li>
     *     <li>Iterationen: 10000</li>
     * </ul>
     * Die Anwendung entschlüsselt privKeyEnc via AES-ECB-128 mit masterKey zu privateKey.
     * @param id
     * @param password
     * @return
     * @throws Exception
     */
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

    /**
     * Der Benutzer wählt eine Identität.
     * Der Benutzer wählt ein Passwort.
     * Die Anwendung erzeugt einen 64 Byte grossen Salt saltmaster aus Zufallszahlen.
     * Die Anwendung bildet masterkey mithilfe der PBKDF2 Funktion mit folgenden Parametern:
     * <ul>
     *     <li>Algorithmus: sha-256</li>
     *     <li>Passwort: password</li>
     *     <li>Salt: saltmaster</li>
     *     <li>Länge: 256 Bit</li>
     *     <li>Iterationen: 10000</li>
     * </ul>
     * Die Anwendung erzeugt ein RSA-2048 Schlüsselpaar privateKey, publicKey. Die Anwendung verschlüsselt privateKey via AES-ECB-128 mit masterkey zu privKeyEnc.
     * @param id
     * @param password
     * @return
     * @throws Exception
     */
    public boolean register(String id, String password)throws Exception{
        URL url = new URL(address + id);
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
        if(returnCode==201){
            return true;
        }else{
            return false;
        }
    }

    /**
     * Die Anwednung sendet eine Nachricht mit den Anforderungen
     * aus der Vorlesung. Die Anforderungen sind aus 'kryptospec.pdf'
     * zu entnehmen
     * @param id
     * @param targetID
     * @param message
     * @return
     * @throws Exception
     */
    public boolean sendMessage(String id, String targetID, String message) throws Exception {
        //fertig
        JSONObject recipient = getUser(targetID);
        String pubKeyRecipient = recipient.getString("pubkey");

        URL url = new URL(address + id +"/message");
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
        String sigRecipient = c.hashAndEncryptSigRecipient(id, cipher, iv, keyRecipient, privateKey);

        JSONObject innerEnvelope = new JSONObject();
        innerEnvelope.put("sourceUserID", id);
        innerEnvelope.put("cipher", cipher);
        innerEnvelope.put("iv", iv);
        innerEnvelope.put("keyRecEnc", keyRecipientEnc);
        innerEnvelope.put("sigRec", sigRecipient);



        String sigService = c.hashAndEncryptSigService(targetID, timestamp, innerEnvelope, privateKey);

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

        if(returnCode==200){
            return true;
        }else{
            return false;
        }
    }

    /**
     * Die Anwednung empfängt alle Nachrichten mit den Anforderungen
     * aus der Vorlesung. Die Anforderungen sind aus 'kryptospec.pdf'
     * zu entnehmen
     * @param id
     * @return
     * @throws Exception
     */
    public String[] receiveMessages(String id) throws Exception{
        StringBuilder result = new StringBuilder();
        URL url = new URL(address + id + "/messages");
        HttpURLConnection httpCon = (HttpURLConnection) url.openConnection();
        httpCon.setDoOutput(true);
        httpCon.setRequestMethod("POST");
        httpCon.setRequestProperty("Content-Type", "application/json");
        httpCon.setRequestProperty("Accept", "application/json");

        long timestamp = System.currentTimeMillis()/1000L;
        String sigService = c.hashAndEncryptIdTime(id, timestamp, privateKey);
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
                String keyRec = c.decryptKeyRecipient(keyRecEnc,privateKey);
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

    /**
     * Eine Hilfsmethode um die öffentlich Daten eines Users anhand seiner ID beim Server
     * anzufragen.
     * @param id
     * @return
     * @throws Exception
     */
    public JSONObject getUser(String id) throws Exception{
        StringBuilder result = new StringBuilder();
        URL url = new URL(address + id);
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

    public void logout(){
        privateKey = "";
    }
}
