package gov.usdot.cv.security.crypto;

import java.nio.ByteBuffer;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.IESWithCipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.engines.IESEngine;

/**
 * Helper class that implements encoding and decoding of the EciesNistP256EncryptedKey element (6.2.25)
 */
public class ECIESProvider {
	
	/**
	 * Length of the authentication tag, which shall be of length 20 for ecies_nistp256. 
	 */
	static public final int authenticationTagLength = 20;
	
	static private final byte[] derivation = ByteBuffer.allocate(8).putLong(0xdeadbeefcafebabeL).array();
	static private final byte[] encoding   = ByteBuffer.allocate(8).putLong(0xebabefacfeebdaedL).array();
	
	private final ECDSAProvider eccProvider;
	private final CipherParameters iesParameters;
	private final IESEngine iesEngine;
	
	/**
	 * Instantiates ECIES provider with new crypto provider
	 */
	public ECIESProvider() {
		this(new CryptoProvider());
	}
	
	/**
	 * Instantiates ECIES provider with specified cryptographic provider
	 * @param cryptoProvider cryptographic provider to use
	 */
	public ECIESProvider(CryptoProvider cryptoProvider) {
		this.eccProvider = cryptoProvider.getSigner();
        iesParameters = new IESWithCipherParameters(derivation, encoding, 128, 128);
		iesEngine = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()));
	}

	/**
	 * ECIES encrypt symmetric encryption key bytes
	 * @param aesEncryptionKeyBytes symmetric encryption key bytes to encrypt
	 * @param ephemeralPrivateKey ephemeral private key
	 * @param recipientECCPublicKey recipient's asymmetric public key
	 * @return encrypted symmetric encryption key bytes
	 * @throws InvalidCipherTextException if encrypting of the symmetric encryption key fails
	 */
	public byte[] encrypt(
			byte[] aesEncryptionKeyBytes, 
			ECPrivateKeyParameters ephemeralPrivateKey, 
			ECPublicKeyParameters recipientECCPublicKey) throws InvalidCipherTextException {
		iesEngine.init(true, ephemeralPrivateKey, recipientECCPublicKey, iesParameters);
		return iesEngine.processBlock(aesEncryptionKeyBytes, 0, aesEncryptionKeyBytes.length);
	}
	
	/**
	 * ECIES decrypt encrypted symmetric encryption key and tag bytes
	 * @param encryptedKeyAndTag encrypted symmetric encryption key and tag bytes to decrypt
	 * @param ephemeralPublicKey ephemeral public key
	 * @param recipientECCPrivateKey recipient's asymmetric private key
	 * @return decrypted symmetric encryption key bytes
	 * @throws InvalidCipherTextException if invalid cipher text
	 */
	public byte[] decrypt(
			byte[] encryptedKeyAndTag, 
			ECPublicKeyParameters ephemeralPublicKey, 
			ECPrivateKeyParameters recipientECCPrivateKey) throws InvalidCipherTextException  {
		iesEngine.init(false, recipientECCPrivateKey, ephemeralPublicKey, iesParameters);
		return iesEngine.processBlock(encryptedKeyAndTag, 0, encryptedKeyAndTag.length);
	}
	
	/**
	 * Encodes EciesNistP256EncryptedKey for a recipient
	 * @param byteBuffer buffer to encode into
	 * @param aesEncryptionKey symmetric encryption key (AES 128 CCM, 16 bytes)
	 * @param recipientECCPublicKey recipient's asymmetric public key
	 * @throws InvalidCipherTextException if encoding of the symmetric encryption key fails
	 */
	public void encode(ByteBuffer byteBuffer, KeyParameter aesEncryptionKey, ECPublicKeyParameters recipientECCPublicKey) throws InvalidCipherTextException {
		AsymmetricCipherKeyPair ephemeralKey = eccProvider.generateKeyPair();
		eccProvider.encodePublicKey(byteBuffer, (ECPublicKeyParameters) ephemeralKey.getPublic());
		byte[] encryptedKeyAndTag = encrypt(aesEncryptionKey.getKey(), (ECPrivateKeyParameters) ephemeralKey.getPrivate(), recipientECCPublicKey);
		byteBuffer.put(encryptedKeyAndTag);
	}
	
	/**
	 * Decodes EciesNistP256EncryptedKey for a recipient
	 * @param byteBuffer buffer to decode from
	 * @param recipientECCPrivateKey recipient's asymmetric private key or null to skip decryption
	 * @return decrypted symmetric encryption key or null if recipientECCPrivateKey is null
	 * @throws InvalidCipherTextException if decoding of the symmetric encryption key fails
	 */
	public KeyParameter decode(ByteBuffer byteBuffer, ECPrivateKeyParameters recipientECCPrivateKey ) throws InvalidCipherTextException {
		ECPublicKeyParameters ephemeralPublicKey = eccProvider.decodePublicKey(byteBuffer);
		byte[] encryptedKeyAndTag = new byte[AESProvider.keyLength + authenticationTagLength];
		byteBuffer.get(encryptedKeyAndTag);
		if ( recipientECCPrivateKey == null )
			return null;
		byte[] decryptedKey = decrypt(encryptedKeyAndTag, ephemeralPublicKey, recipientECCPrivateKey);
		return new KeyParameter(decryptedKey);
	}
	
}
