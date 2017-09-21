package gov.usdot.cv.security.crypto;


import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * A collection of cryptographic helper functions to be used in a single thread
 */
public class CryptoHelper {

	private final CryptoProvider cryptoProvider;
	
	/**
	 * Instantiates cryptographic helper with new CryptoHelper
	 */
	public CryptoHelper() {
		this(new CryptoProvider());
	}
	
	/**
	 * Instantiates cryptographic helper with supplied cryptographic provider
	 * @param cryptoProvider for use by this helper
	 */
	public CryptoHelper(CryptoProvider cryptoProvider) {
		this.cryptoProvider = cryptoProvider;
	}
	
	/**
	 * Calculates SHA-256 digest of the bytes provided
	 * @param bytes to calculate the digest of
	 * @return calculated SHA-256 digest
	 */
	public byte[] computeDigest(byte[] bytes) {
		return computeDigest(bytes, 0, bytes.length);
	}
	
	/**
	 * Calculates SHA-256 digest of the bytes provided
	 * @param bytes to calculate the digest of
	 * @param start of the bytes for digest
	 * @param length of the bytes for digest
	 * @return calculated SHA-256 digest
	 */
	public byte[] computeDigest(byte[] bytes, int start, int length ) {
		return cryptoProvider.computeDigest(bytes, start, length);
	}
	
	/**
	 * Generates random sequence of bytes
	 * @param length of the sequence to generate
	 * @return generated random sequence of bytes
	 */
	public static byte[] getSecureRandomBytes(int length) {
		byte[] randomBytes = new byte[length];
		CryptoProvider.getSecureRandom().nextBytes(randomBytes);
		return randomBytes;
	}
	
	/**
	 * Encrypts clear text
	 * @param key symmetric key to use for encryption
	 * @param nonce to use
	 * @param clearText to encrypt
	 * @return encrypted text
	 * @throws CryptoException if encryption fails
	 */
	public byte[] encryptSymmetric(KeyParameter key, byte[] nonce, byte[] clearText) throws CryptoException {
		return cryptoProvider.getSymmetricCipher().encrypt(key, nonce, clearText);
	}
	
	/**
	 * Decrypts cipher text
	 * @param key symmetric key to use for decryption
	 * @param nonce to use
	 * @param cipherText to decrypt
	 * @return clear text
	 * @throws CryptoException if encryption fails
	 */
	public byte[] decryptSymmetric(KeyParameter key, byte[] nonce, byte[] cipherText) throws CryptoException {
		return cryptoProvider.getSymmetricCipher().decrypt(key, nonce, cipherText);
	}
	
	/**
	 * Computes message signature
	 * @param message bytes to compute a signature for
	 * @param key private signing key to use
	 * @return message signature
	 */
	public ECDSASignature computeSignature(byte[] message, ECPrivateKeyParameters key) {
		return cryptoProvider.getSigner().computeSignature(message, key);
	}
	
	/**
	 * Computes message signature
	 * @param message bytes to compute a signature for
	 * @param start start position in the message
	 * @param length bytes count to use
	 * @param key private signing key to use
	 * @return message signature
	 */
	public ECDSASignature computeSignature(byte[] message, int start, int length, ECPrivateKeyParameters key) {
		return cryptoProvider.getSigner().computeSignature(message, start, length, key);
	}
	
	/**
	 * Validates message signature
	 * @param message bytes to validate
	 * @param key public signing key to use
	 * @param signature to validate
	 * @return true if the signature is valid and false otherwise
	 */
	public boolean verifySignature(byte[] message, ECPublicKeyParameters key, ECDSASignature signature) {
		return message != null ? cryptoProvider.getSigner().verifySignature(message, key, signature) : false;
	}
	
	/**
	 * Validates message signature
	 * @param message the message as bytes
	 * @param start start position in the message
	 * @param length bytes count to use
	 * @param key public signing key to use
	 * @param signature to validate
	 * @return true if the signature is valid and false otherwise
	 */
	public boolean verifySignature(byte[] message, int start, int length, ECPublicKeyParameters key, ECDSASignature signature) {
		return cryptoProvider.getSigner().verifySignature(message, start, length, key, signature);
	}
}
