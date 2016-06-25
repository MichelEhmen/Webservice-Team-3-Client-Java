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

	private static String privateKeyString;
	private static String publicKeyString;
	private static PrivateKey privateKey;
	private static PublicKey publicKey;
	private static String masterkey;
	private static String innerEnvelope;
	private static byte[] salt;
	private static byte[] privateKeyUserEnc;

	public static void main(String[] args) throws Exception {
//		testJceWorkingCorrectly();
//		generateKeyPair();
		generateSalt();
		generateMasterkey("123456");
//		encryptPrivateKey(privateKeyUser, masterkey);
//		decryptPrivateKey(privateKeyUserEnc, masterkey);
//		createInnerEnvelope("PeterZwegat", "Hallo, wie geht es dir?");
	}

	public static void testJceWorkingCorrectly() throws NoSuchAlgorithmException {
		int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
		System.out.println(maxKeyLen);
		// Ergebnis: 128 funktioniert nicht korrekt, Ergebnis: 2147483647
		// funktioniert korrekt
		// https://ubuntuincident.wordpress.com/2011/04/14/install-the-java-cryptography-extension-jce/

	}

	public static byte[] generateSalt() {
		byte[] saltF = new byte[64];
		RANDOM.nextBytes(saltF);
		salt = saltF;
		return saltF;
	}

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

	private static String generateMasterkey(String password) throws Exception {
		int iterations = 10000;
		char[] chars = password.toCharArray();

		PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 128);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		byte[] hash = skf.generateSecret(spec).getEncoded();
		masterkey = toHex(hash);
		System.out.println(iterations + ":" + toHex(salt) + ":" + toHex(hash));
		return toHex(hash);

	}

	public static void generateKeyPair() throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair pair = keyGen.generateKeyPair();
		byte[] pubKey = pair.getPublic().getEncoded();
		publicKey = pair.getPublic();
		byte[] privKey = pair.getPrivate().getEncoded();
		privateKey = pair.getPrivate();
		
		StringBuffer retStringPublic = new StringBuffer();
		for (int i = 0; i < pubKey.length; ++i) {
			retStringPublic.append(Integer.toHexString(0x0100 + (pubKey[i] & 0x00FF)).substring(1));
		}
		publicKeyString = retStringPublic.toString();
		System.out.println("public key: "+publicKeyString);

		StringBuffer retStringPrivate = new StringBuffer();
		for (int i = 0; i < privKey.length; ++i) {
			retStringPrivate.append(Integer.toHexString(0x0100 + (privKey[i] & 0x00FF)).substring(1));
		}
		privateKeyString = retStringPrivate.toString();
		System.out.println("private key: "+privateKeyString);
	}
	
	public static byte[] encryptPrivateKey(String privateKey, String masterkey) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(masterkey.getBytes("UTF-8"), "AES");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		privateKeyUserEnc = cipher.doFinal(privateKey.getBytes("UTF-8"));
		return cipher.doFinal(privateKey.getBytes("UTF-8"));
	}

	public static String decryptPrivateKey(byte[] privateKeyEnc, String newMasterkey) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(newMasterkey.getBytes("UTF-8"), "AES");
		cipher.init(Cipher.DECRYPT_MODE, key);
		String privateKeyUserDec = new String(cipher.doFinal(privateKeyEnc), "UTF-8");
		System.out.println(privateKeyUserDec);
		return new String(cipher.doFinal(privateKeyEnc), "UTF-8");
	}

	public static void createInnerEnvelope(String username, String message) throws Exception {
		byte[] keyRecipientBytes = new byte[10];
		RANDOM.nextBytes(keyRecipientBytes);
		String keyRecipient = Base64.getEncoder().encodeToString(keyRecipientBytes);

		byte[] ivBytes = new byte[10];
		RANDOM.nextBytes(ivBytes);
		String iv = Base64.getEncoder().encodeToString(ivBytes);
		
		Cipher cipherMessage = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(keyRecipient.getBytes("UTF-8"), "AES");
		cipherMessage.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv.getBytes("UTF-8")));
		byte[] cipherMessageBytes = cipherMessage.doFinal(message.getBytes("UTF-8"));
		String cipherMessageString = Base64.getEncoder().encodeToString(cipherMessageBytes);
		
		Cipher cipherKeyRecipient = Cipher.getInstance("RSA");
		cipherKeyRecipient.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] keyRecipientEncBytes = cipherKeyRecipient.doFinal(keyRecipient.getBytes("UTF-8"));
		String keyRecipientEnc = Base64.getEncoder().encodeToString(keyRecipientEncBytes);
		
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		String partInnerEnvelope = username+":"+ cipherMessageString+":"+iv+":"+keyRecipientEnc;
		
		md.update(partInnerEnvelope.getBytes("UTF-8")); 
		byte[] sigRecipientBytes = md.digest();
		String sigRecipient = Base64.getEncoder().encodeToString(sigRecipientBytes);
		
		innerEnvelope = partInnerEnvelope+":"+sigRecipient;

	}
	
	private static void createOuterEnvelope() {
		
		
	}

}
