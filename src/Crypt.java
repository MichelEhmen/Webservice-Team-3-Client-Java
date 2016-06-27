import java.math.BigInteger;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypt {

	private static final SecureRandom RANDOM = new SecureRandom();

	private KeyPair kPair;


	public static void main(String[] args) throws Exception {
		Crypt c = new Crypt();
		// c.testJceWorkingCorrectly();
		c.generateKeyPair();
		String privkeyst = c.getPrivateKeyString();
		System.out.println("=="+privkeyst);
		PublicKey pubk = c.getPublicKey();
		PrivateKey prik = c.getPrivateKey();
		String s = c.generateSaltmaster();
		System.out.println("===========================");
		System.out.println(s);
		String mk = c.generateMasterkey("ads", s);
		String privkeyenc = c.encryptPrivateKey(privkeyst, mk);
		System.out.println(c.decryptPrivateKey(privkeyenc, mk));
		String kr = c.generateKeyRecipient();
		System.out.println(kr);
		String iv = c.generateIv();
		System.out.println("=="+iv.length());
		String em = c.encryptMessage("Hallo, wie geht es denn so?", kr, iv);
		System.out.println(c.decryptMessage(em, kr, iv));
		String ekr = c.encryptKeyRecipient(kr, pubk);
		System.out.println("=="+ekr);
		String krd = c.decryptKeyRecipient(ekr, prik);
		System.out.println(krd);
		String sr = c.hashSigRecipient("Daniel",em, iv, ekr, privkeyst);

	}

	public void testJceWorkingCorrectly() throws Exception {
		int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
		System.out.println(maxKeyLen);
		// Ergebnis: 128 funktioniert nicht korrekt, Ergebnis: 2147483647
		// funktioniert korrekt
	}

	public String generateSaltmaster() throws Exception {
		byte[] saltmasterBytes = new byte[64];
		RANDOM.nextBytes(saltmasterBytes);
		String saltmaster = toHex(saltmasterBytes);
		return saltmaster;
	}

	public String generateKeyRecipient() throws Exception {
		byte[] keyRecipientBytes = new byte[16];
		RANDOM.nextBytes(keyRecipientBytes);
		String keyRecipient = toHex(keyRecipientBytes);
		return keyRecipient;
	}

	public String generateIv() throws Exception {
		byte[] ivBytes = new byte[16];
		RANDOM.nextBytes(ivBytes);
		String iv = toHex(ivBytes);
		return iv;
	}

	public String generateMasterkey(String password, String saltmaster) throws Exception {
		int iterations = 10000;
		char[] chars = password.toCharArray();
		byte[] saltmasterBytes = hexStringToByteArray(saltmaster);

		PBEKeySpec spec = new PBEKeySpec(chars, saltmasterBytes, iterations, 128);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		byte[] hash = skf.generateSecret(spec).getEncoded();

		return toHex(hash);
	}

	public void generateKeyPair() throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair pair = keyGen.generateKeyPair();
		kPair = pair;
	}

	public String getPublicKeyString() {
		byte[] pubKey = kPair.getPublic().getEncoded();

		StringBuffer retStringPublic = new StringBuffer();
		for (int i = 0; i < pubKey.length; ++i) {
			retStringPublic.append(Integer.toHexString(0x0100 + (pubKey[i] & 0x00FF)).substring(1));
		}
		String publicKeyString = retStringPublic.toString();
		return publicKeyString;

	}

	public String getPrivateKeyString() {
		byte[] privKey = kPair.getPrivate().getEncoded();

		StringBuffer retStringPrivate = new StringBuffer();
		for (int i = 0; i < privKey.length; ++i) {
			retStringPrivate.append(Integer.toHexString(0x0100 + (privKey[i] & 0x00FF)).substring(1));
		}
		String privateKeyString = retStringPrivate.toString();
		return privateKeyString;
	}

	public PublicKey getPublicKey() {
		PublicKey publicKey = kPair.getPublic();
		return publicKey;

	}

	public PrivateKey getPrivateKey() {
		PrivateKey privateKey = kPair.getPrivate();
		return privateKey;
	}

	public String encryptPrivateKey(String privateKey, String masterkey) throws Exception {
		byte[] masterkeyBytes = hexStringToByteArray(masterkey);
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(masterkeyBytes, "AES");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] privateKeyEncBytes= cipher.doFinal(privateKey.getBytes("UTF-8"));
		String privateKeyEnc = toHex(privateKeyEncBytes);
		return privateKeyEnc;
	}

	public String decryptPrivateKey(String privateKeyEnc, String masterkey)
			throws Exception {
		byte[] masterkeyBytes = hexStringToByteArray(masterkey);
		byte[] privateKeyEncBytes = hexStringToByteArray(privateKeyEnc);
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(masterkeyBytes, "AES");
		cipher.init(Cipher.DECRYPT_MODE, key);
		String privateKey = new String(cipher.doFinal(privateKeyEncBytes), "UTF-8");
		return privateKey;
	}


	public String encryptHash(byte[] hash, String privateKey) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(privateKey.getBytes("UTF-8"), "AES");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] hashEncBytes= cipher.doFinal(hash);
		String hashEnc = toHex(hashEncBytes);
		return hashEnc;
	}

	public String decryptHash(String encHash, String privateKey) throws Exception {
		byte[] HashEncBytes = hexStringToByteArray(encHash);
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(privateKey.getBytes("UTF-8"), "AES");
		cipher.init(Cipher.DECRYPT_MODE, key);
		String hashEnc = new String(cipher.doFinal(HashEncBytes), "UTF-8");
		return hashEnc;
	}


	public String encryptMessage(String message, String keyRecipient, String iv) throws Exception {
		byte[] keyRecipientBytes = hexStringToByteArray(keyRecipient);
		byte[] ivBytes = hexStringToByteArray(iv);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(keyRecipientBytes, "AES");
		cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
		byte[] encryptedMessageBytes = cipher.doFinal(message.getBytes("UTF-8"));
		String encryptedMessage = toHex(encryptedMessageBytes);
		return encryptedMessage;
	}

	public String decryptMessage(String encryptedMessage, String keyRecipient, String iv) throws Exception {
		byte[] keyRecipientBytes = hexStringToByteArray(keyRecipient);
		byte[] ivBytes = hexStringToByteArray(iv);
		byte[] encryptedMessageByte = hexStringToByteArray(encryptedMessage);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(keyRecipientBytes, "AES");
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
		String message = new String(cipher.doFinal(encryptedMessageByte), "UTF-8");
		return message;
	}

	public String encryptKeyRecipient(String keyRecipient, PublicKey publicKey) throws Exception {
		//byte[] keyRecipientBytes = hexStringToByteArray(keyRecipient);
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] keyRecipientEncBytes = cipher.doFinal(keyRecipient.getBytes("UTF-8"));
		String keyRecipientEnc = toHex(keyRecipientEncBytes);
		return keyRecipientEnc;
	}

	public String decryptKeyRecipient(String keyRecipientEnc, PrivateKey privateKey) throws Exception {
		byte[] keyRecipientEncBytes = hexStringToByteArray(keyRecipientEnc);
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		String keyRecipient = new String(cipher.doFinal(keyRecipientEncBytes), "UTF-8");
		return keyRecipient;
	}

	//privateKey können nicht als Schlüssel für AES Encryption verwendet werden - zu groß
	public String hashSigRecipient(String fromUser, String encryptedMessage, String iv, String keyRecipientEnc, String privateKey)
			throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		String partData = fromUser + encryptedMessage + iv + keyRecipientEnc;
		md.update(partData.getBytes("UTF-8"));
		byte[] sigRecipientBytes = md.digest();

		String sigRecipient = toHex(sigRecipientBytes);
		//String sigRecipient = encryptHash(sigRecipientBytes, privateKey);

		return sigRecipient;

	}

	//privateKey können nicht als Schlüssel für AES Encryption verwendet werden - zu groß
	public String hashSigService(String toUser, Timestamp timestamp, String innerEnvelope, String privateKey) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		String partData = toUser + timestamp + innerEnvelope;
		md.update(partData.getBytes("UTF-8"));
		byte[] sigServiceBytes = md.digest();

		String sigService = toHex(sigServiceBytes);
		//String sigService = encryptHash(sigServiceBytes, privateKey);

		return sigService;
	}

	// ab hier Hilfsmethoden
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

	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
					+ Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}

}
