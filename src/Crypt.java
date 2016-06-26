
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypt {

	private static final Random RANDOM = new SecureRandom();

	private static KeyPair kPair;

	public static void main(String[] args) throws Exception {
		// testJceWorkingCorrectly();
		// generateKeyPair();
		// getPrivateKey();
		// PublicKey pk = getPublicKey();
		// generateSalt();
		// generateMasterkey("123456");
		// encryptPrivateKey(privateKeyUser, masterkey);
		// decryptPrivateKey(privateKeyUserEnc, masterkey);
		// String kr = generateKeyRecipient();
		// String iv = generateIv();
		// byte[] em = encryptMessage("Hallo, wie geht es denn so?", kr, iv);
		// decryptMessage(em, kr, iv);
		// byte[] ekr = encryptKeyRecipient(kr, pk);
		// decryptKeyRecipient(ekr, pk);


	}

	public static void testJceWorkingCorrectly() throws NoSuchAlgorithmException {
		int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
		System.out.println(maxKeyLen);
		// Ergebnis: 128 funktioniert nicht korrekt, Ergebnis: 2147483647
		// funktioniert korrekt
		// https://ubuntuincident.wordpress.com/2011/04/14/install-the-java-cryptography-extension-jce/

	}

	public static byte[] generateSalt() {
		byte[] salt = new byte[64];
		RANDOM.nextBytes(salt);
		return salt;
	}

	public static String generateMasterkey(String password, byte[] salt) throws Exception {
		int iterations = 10000;
		char[] chars = password.toCharArray();

		PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 128);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		byte[] hash = skf.generateSecret(spec).getEncoded();
		return toHex(hash);

	}

	public static void generateKeyPair() throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair pair = keyGen.generateKeyPair();
		kPair = pair;
	}

	public static String getPublicKeyString() {
		byte[] pubKey = kPair.getPublic().getEncoded();

		StringBuffer retStringPublic = new StringBuffer();
		for (int i = 0; i < pubKey.length; ++i) {
			retStringPublic.append(Integer.toHexString(0x0100 + (pubKey[i] & 0x00FF)).substring(1));
		}
		String publicKeyString = retStringPublic.toString();
		return publicKeyString;

	}

	public static String getPrivateKeyString() {
		byte[] privKey = kPair.getPrivate().getEncoded();

		StringBuffer retStringPrivate = new StringBuffer();
		for (int i = 0; i < privKey.length; ++i) {
			retStringPrivate.append(Integer.toHexString(0x0100 + (privKey[i] & 0x00FF)).substring(1));
		}
		String privateKeyString = retStringPrivate.toString();
		return privateKeyString;
	}

	public static PublicKey getPublicKey() {
		PublicKey publicKey = kPair.getPublic();
		return publicKey;

	}

	public static PrivateKey getPrivateKey() {
		PrivateKey privateKey = kPair.getPrivate();
		return privateKey;
	}

	public static byte[] encryptPrivateKey(String privateKey, String masterkey) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(masterkey.getBytes("UTF-8"), "AES");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] privateKeyEnc = cipher.doFinal(privateKey.getBytes("UTF-8"));
		return privateKeyEnc;
	}

	public static String decryptPrivateKey(byte[] privateKeyEnc, String newMasterkey) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(newMasterkey.getBytes("UTF-8"), "AES");
		cipher.init(Cipher.DECRYPT_MODE, key);
		String privateKey = new String(cipher.doFinal(privateKeyEnc), "UTF-8");
		return privateKey;
	}

	public static String generateKeyRecipient() throws Exception {
		byte[] keyRecipientBytes = new byte[10];
		RANDOM.nextBytes(keyRecipientBytes);
		String keyRecipient = Base64.getEncoder().encodeToString(keyRecipientBytes);
		return keyRecipient;
	}

	public static String generateIv() throws Exception {
		byte[] ivBytes = new byte[10];
		RANDOM.nextBytes(ivBytes);
		String iv = Base64.getEncoder().encodeToString(ivBytes);
		return iv;
	}

	public static byte[] encryptMessage(String message, String keyRecipient, String iv) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(keyRecipient.getBytes("UTF-8"), "AES");
		cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv.getBytes("UTF-8")));
		byte[] encryptedMessage = cipher.doFinal(message.getBytes("UTF-8"));
		return encryptedMessage;
	}

	public static String decryptMessage(byte[] encryptedMessage, String keyRecipient, String iv) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(keyRecipient.getBytes("UTF-8"), "AES");
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv.getBytes("UTF-8")));
		String message = new String(cipher.doFinal(encryptedMessage), "UTF-8");
		System.out.println(message);
		return message;
	}

	public static byte[] encryptKeyRecipient(String keyRecipient, PublicKey publicKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] keyRecipientEnc = cipher.doFinal(keyRecipient.getBytes("UTF-8"));
		System.out.println(Base64.getEncoder().encodeToString(keyRecipientEnc));
		return keyRecipientEnc;
	}

	// funktioniert leider noch nicht so richtig :-/
	public static String decryptKeyRecipient(byte[] keyRecipientEnc, PublicKey publicKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		String keyRecipient = new String(cipher.doFinal(keyRecipientEnc), "UTF-8");
		System.out.println(keyRecipient);
		return keyRecipient;
	}

	// Noch nicht ganz richtig -> Zitat kryptospec: Die Anwendung bildet eine
	// digitale Signatur sig_recipient mit Hilfe von SHA-256 und privkey_user
	// über Identität, Cipher, iv und key_recipient_enc.
	// Verstehe nicht wirklich, wie ich das einbauen soll xD
	public static String hashSigRecipient(String fromUser, String cipher, String iv, String keyRecipientEnc)
			throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		String partData = fromUser + cipher + iv + keyRecipientEnc;
		md.update(partData.getBytes("UTF-8"));
		byte[] sigRecipientBytes = md.digest();
		String sigRecipient = Base64.getEncoder().encodeToString(sigRecipientBytes);
		return sigRecipient;

	}

	// Noch nicht ganz richtig -> Zitat kryptospec: Die Anwendung bildet eine
	// digitale Signatur sig_service mit Hilfe von SHA-256 und privkey_user über
	// innerer Umschlag, timestamp, Empfänger.
	// Verstehe nicht wirklich, wie ich das einbauen soll xD
	public static String hashSigService(String toUser, Timestamp timestamp, String innerEnvelope) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		String partData = toUser + timestamp + innerEnvelope;
		md.update(partData.getBytes("UTF-8"));
		byte[] sigRecipientBytes = md.digest();
		String sigRecipient = Base64.getEncoder().encodeToString(sigRecipientBytes);
		return sigRecipient;
	}

	// Hilfsmethode bei der PBKDF2 Funktion - nicht weiter beachten
	private static String toHex(byte[] array) throws Exception {
		BigInteger bi = new BigInteger(1, array);
		String hex = bi.toString(16);
		int paddingLength = (array.length * 2) - hex.length();
		if (paddingLength > 0) {
			return String.format("%0" + paddingLength + "d", 0) + hex;
		} else {
			return hex;
		}
	}

}
