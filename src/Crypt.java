import org.json.JSONObject;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class Crypt {

    private static final SecureRandom RANDOM = new SecureRandom();

    private KeyPair kPair;


    public static void main(String[] args) throws Exception {
        Crypt c = new Crypt();
        // c.testJceWorkingCorrectly();
        c.generateKeyPair();
//        c.getPublicKey();
        String privkeyst = c.getPrivateKey();
        String pubkeyst = c.getPublicKey();
        System.out.println(pubkeyst);
        System.out.println(privkeyst);
        String s = c.generateSaltmaster();
        System.out.println(s);
        String mk = c.generateMasterkey("ads", s);
        String privkeyenc = c.encryptPrivateKey(privkeyst, mk);
        System.out.println(c.decryptPrivateKey(privkeyenc, mk));
        String kr = c.generateKeyRecipient();
        System.out.println(kr);
        String iv = c.generateIv();
        System.out.println(iv);
        String em = c.encryptMessage("Hallo, wie geht es denn so?", kr, iv);
        System.out.println(c.decryptMessage(em, kr, iv));
        String ekr = c.encryptKeyRecipient(kr, pubkeyst);
        System.out.println(ekr);
        String krd = c.decryptKeyRecipient(ekr, privkeyst);
        System.out.println(krd);
        String sr = c.hashAndEncryptSigRecipient("Daniel", em, iv, ekr, privkeyst);
    }

    /*
    * Überprüft ob JCE (Java Cryptography Extension) richtig funktioniert.
    * Dies wird benötigt, um ein korrektes Ergebnis bei den kryptographischen Verfahren zu erhalten.
    * Überprüfung:
    * Ergebnis: 128 funktioniert nicht korrekt, Ergebnis: 2147483647 funktioniert korrekt
    * */
    public void testJceWorkingCorrectly() throws Exception {
        int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
        System.out.println(maxKeyLen);
    }

	/*
    * Hier werden diverse Werte für die Nutzung in Verschlüsselungs- und Entschlüsselungsverfahren
	* generiert. Diese werden zunächt in Bytes generiert und dann via Base64 enkodiert.
	* */

    public String generateSaltmaster() {
        byte[] saltmasterBytes = new byte[64];
        RANDOM.nextBytes(saltmasterBytes);
        String saltmaster = Base64.getEncoder().encodeToString(saltmasterBytes);
        return saltmaster;
    }

    public String generateKeyRecipient() {
        byte[] keyRecipientBytes = new byte[16];
        RANDOM.nextBytes(keyRecipientBytes);
        String keyRecipient = Base64.getEncoder().encodeToString(keyRecipientBytes);
        return keyRecipient;
    }

    public String generateIv() {
        byte[] ivBytes = new byte[16];
        RANDOM.nextBytes(ivBytes);
        String iv = Base64.getEncoder().encodeToString(ivBytes);
        return iv;
    }

    public void generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        kPair = pair;
    }

    public String getPublicKey() {
        byte[] pubKey = kPair.getPublic().getEncoded();
        String publicKeyString = Base64.getEncoder().encodeToString(pubKey);
        return publicKeyString;

    }

    public String getPrivateKey() {
        byte[] privKey = kPair.getPrivate().getEncoded();
        String privateKeyString = Base64.getEncoder().encodeToString(privKey);

        return privateKeyString;
    }


    public String generateMasterkey(String password, String saltmaster) throws Exception {
        if (password != null && saltmaster != null) {
            int iterations = 10000;
            char[] chars = password.toCharArray();
            byte[] saltmasterBytes = Base64.getDecoder().decode(saltmaster);

            PBEKeySpec spec = new PBEKeySpec(chars, saltmasterBytes, iterations, 128);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

            byte[] masterkeyBytes = skf.generateSecret(spec).getEncoded();
            String masterkey = Base64.getEncoder().encodeToString(masterkeyBytes);
            return masterkey;
        } else {
            throw new Exception("Generate maseter key is not possible.");
        }
    }

    /*
    * Hier wird die AES/ECB Verschlüsselung auf den Private Key angewandt.
    * Als Schlüssel dient der generierte Masterkey.
    * Anschließend die Entschlüsselung mit dem selben Verfahren. Die Umkodierung
    * geschieht über Base64.
    * */
    public String encryptPrivateKey(String privateKey, String masterkey) throws Exception {
        if (privateKey != null && masterkey != null) {
            byte[] masterkeyBytes = Base64.getDecoder().decode(masterkey);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
            SecretKeySpec key = new SecretKeySpec(masterkeyBytes, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] privateKeyEncBytes = cipher.doFinal(privateKey.getBytes("UTF-8"));
            String privateKeyEnc = Base64.getEncoder().encodeToString(privateKeyEncBytes);
            return privateKeyEnc;
        } else {
            throw new Exception("Encrypt private Key is not possible.");
        }
    }

    public String decryptPrivateKey(String privateKeyEnc, String masterkey)
            throws Exception {
        if (privateKeyEnc != null && masterkey != null) {
            byte[] masterkeyBytes = Base64.getDecoder().decode(masterkey);
            byte[] privateKeyEncBytes = Base64.getDecoder().decode(privateKeyEnc);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
            SecretKeySpec key = new SecretKeySpec(masterkeyBytes, "AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            String privateKey = new String(cipher.doFinal(privateKeyEncBytes), "UTF-8");
            return privateKey;
        } else {
            throw new Exception("Decrypt private Key is not possible.");
        }
    }

    /*
    * Hier wird die AES/CBC Verschlüsselung auf die Nachricht angewandt.
    * Als Schlüssel dient Key Recipient. Zudem wird ein Initialiserungsvektor aus Zufallszahlen eingesetzt.
    * Anschließend die Entschlüsselung mit dem selben Verfahren. Die Umkodierung
    * geschieht über Base64.
    * */
    public String encryptMessage(String message, String keyRecipient, String iv) throws Exception {
        if (message != null && keyRecipient != null && iv != null) {
            byte[] keyRecipientBytes = Base64.getDecoder().decode(keyRecipient);
            byte[] ivBytes = Base64.getDecoder().decode(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
            SecretKeySpec key = new SecretKeySpec(keyRecipientBytes, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
            byte[] encryptedMessageBytes = cipher.doFinal(message.getBytes("UTF-8"));
            String encryptedMessage = Base64.getEncoder().encodeToString(encryptedMessageBytes);
            return encryptedMessage;
        } else {
            throw new Exception("Encrypt message is not possible.");
        }
    }

    public String decryptMessage(String encryptedMessage, String keyRecipient, String iv) throws Exception {
        if (encryptedMessage != null && keyRecipient != null && iv != null) {
            byte[] keyRecipientBytes = Base64.getDecoder().decode(keyRecipient);
            byte[] ivBytes = Base64.getDecoder().decode(iv);
            byte[] encryptedMessageByte = Base64.getDecoder().decode(encryptedMessage);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
            SecretKeySpec key = new SecretKeySpec(keyRecipientBytes, "AES");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
            String message = new String(cipher.doFinal(encryptedMessageByte), "UTF-8");
            return message;
        } else {
            throw new Exception("Decrypt message is not possible.");
        }
    }

    /*
    * Hier wird die RSA Verschlüsselung auf keyRecipient angewandt.
    * Als Schlüssel wird der Public Key benutzt.
    * Anschließend die Entschlüsselung mit dem selben Verfahren. Die Umkodierung
    * geschieht über Base64.
    * */
    public String encryptKeyRecipient(String keyRecipient, String publicKey) throws Exception {
        if (keyRecipient != null && publicKey != null) {
            byte[] publicBytes = java.util.Base64.getDecoder().decode(publicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pubKey = keyFactory.generatePublic(keySpec);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            byte[] contentEncBytes = cipher.doFinal(keyRecipient.getBytes("UTF-8"));
            String contentEnc = Base64.getEncoder().encodeToString(contentEncBytes);
            return contentEnc;
        } else {
            throw new Exception("Encrypt key recipient is not possible.");
        }

    }

    public String decryptKeyRecipient(String encKeyRecipient, String privateKey) throws Exception {
        if (encKeyRecipient != null && privateKey != null) {
            byte[] privateBytes = java.util.Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privKey = keyFactory.generatePrivate(keySpec);

            byte[] contentBytes = Base64.getDecoder().decode(encKeyRecipient);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privKey);
            String content = new String(cipher.doFinal(contentBytes), "UTF-8");
            return content;
        } else {
            throw new Exception("Decrypt key recipient is not possible.");
        }

    }

    /*
    * In den folgenden Methoden werden verschiedene Teile der Nachricht mit SHA256 gehasht
    * und anschließend mit dem Private Key RSA verschlüsselt.
    * Die Umkodierung geschieht über Base64.
    * */
    public String hashAndEncryptSigRecipient(String fromUser, String encryptedMessage, String iv, String keyRecipientEnc, String privateKey)
            throws Exception {
        if (fromUser != null && encryptedMessage != null && encryptedMessage != iv && keyRecipientEnc != null && privateKey != null) {
            byte[] privateBytes = java.util.Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privKey = keyFactory.generatePrivate(keySpec);

            Signature sig = Signature.getInstance("SHA256WithRSA");
            String data = fromUser + encryptedMessage + iv + keyRecipientEnc;
            byte[] dataBytes = data.getBytes();
            sig.initSign(privKey);
            sig.update(dataBytes);
            byte[] signatureBytes = sig.sign();
            String encryptedHash = Base64.getEncoder().encodeToString(signatureBytes);

            return encryptedHash;
        } else {
            throw new Exception("Hash and encrypt the signature recipient is not possible.");
        }
    }

    public String hashAndEncryptSigService(String toUser, long timestamp, JSONObject innerEnvelope, String privateKey) throws Exception {
        if (toUser != null && timestamp != 0 && innerEnvelope != null && privateKey != null) {
            byte[] privateBytes = java.util.Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privKey = keyFactory.generatePrivate(keySpec);

            Signature sig = Signature.getInstance("SHA256WithRSA");
            String data = toUser + timestamp + innerEnvelope;
            byte[] dataBytes = data.getBytes();
            sig.initSign(privKey);
            sig.update(dataBytes);
            byte[] signatureBytes = sig.sign();

            String encryptedHash = Base64.getEncoder().encodeToString(signatureBytes);

            return encryptedHash;
        } else {
            throw new Exception("Hash and encrypt the signature service is not possible.");
        }
    }


}
