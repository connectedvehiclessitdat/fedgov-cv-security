package gov.usdot.cv.security.msg;

import gov.usdot.cv.security.cert.Certificate;
import gov.usdot.cv.security.cert.CertificateException;
import gov.usdot.cv.security.cert.CertificateManager;
import gov.usdot.cv.security.crypto.AESProvider;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.crypto.ECDSAProvider;
import gov.usdot.cv.security.crypto.ECIESProvider;
import gov.usdot.cv.security.util.vector.EncodableVectorItem;
import gov.usdot.cv.security.util.vector.VectorException;

import java.nio.ByteBuffer;
import java.util.Arrays;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Helper class for encoding and decoding recipient information (6.2.24 RecipientInfo)
 */
public class RecipientInfo implements EncodableVectorItem<RecipientInfo> {
	
	private static final Logger log = Logger.getLogger(RecipientInfo.class);
	
	private byte[] certID8;
	private KeyParameter aesEncryptionKey;
	private ECPublicKeyParameters encryptionPublicKey;
	private ECPrivateKeyParameters encryptionPrivateKey;
	private ECIESProvider eciesProvider;
	
	/**
	 * Constructs recipient information instance suitable for encoding
	 * @param cryptoProvider cryptographic provider helper
	 * @param certID8 recipient ID
	 * @param aesEncryptionKey AES symmetrical key
	 * @throws CertificateException if certificate is not found or does not contain public encryption key 
	 */
	public RecipientInfo(CryptoProvider cryptoProvider, byte[] certID8, KeyParameter aesEncryptionKey) throws CertificateException {
		assert(certID8 != null && certID8.length == 8 );
		assert(aesEncryptionKey != null && aesEncryptionKey.getKey().length == AESProvider.keyLength);
		assert(cryptoProvider != null);
		this.certID8 = certID8;
		this.aesEncryptionKey = aesEncryptionKey;
		Certificate certificate = CertificateManager.get(certID8);
		if ( certificate == null )
			throw new CertificateException(String.format("Certificate for CertID8 %s was not found", Hex.encodeHexString(certID8)));
		encryptionPublicKey = certificate.getEncryptionPublicKey();
		if ( encryptionPublicKey == null )
			throw new CertificateException(String.format("Certificate for CertID8 %s does not contain public encryption key", Hex.encodeHexString(certID8)));
		eciesProvider = cryptoProvider.getECIESProvider();
	}
	
	/**
	 * Constructs recipient information instance suitable for decoding
	 * @param cryptoProvider cryptographic provider helper
	 * @param certID8 recipient ID
	 */
	public RecipientInfo(CryptoProvider cryptoProvider, byte[] certID8) {
		assert(certID8 != null && certID8.length == 8 );
		assert(cryptoProvider != null);
		this.certID8 = certID8;
		Certificate certificate = CertificateManager.get(certID8);
		if ( certificate != null ) {
			encryptionPrivateKey = certificate.getEncryptionPrivateKey();
			if ( encryptionPrivateKey == null )
				log.info(String.format("Certificate for CertID8 %s does not contain private encryption key", Hex.encodeHexString(certID8)));
		} else {
			log.info(String.format("Certificate for CertID8 %s was not found", Hex.encodeHexString(certID8)));
		}
		eciesProvider = cryptoProvider.getECIESProvider();
	}
	
	/**
	 * Constructs recipient information instance as the result of decoding.
	 * Only getCertID8() and getAesEncryptionKey() method calls are allowed for this type of an instance
	 * @param certID8 recipient ID
	 * @param aesEncryptionKey AES symmetrical key
	 */
	private RecipientInfo(byte[] certID8, KeyParameter aesEncryptionKey) {
		this.aesEncryptionKey = aesEncryptionKey;
	}
	
	/**
	 * Retrieves recipient ID
	 * @return recipient ID
	 */
	public byte[] getCertID8() { 
		return certID8; 
	}
	
	/**
	 * Retrieves AES symmetrical key
	 * @return AES symmetrical key
	 */
	public KeyParameter getAesEncryptionKey() { 
		return aesEncryptionKey; 
	}

	@Override
	public int getLength() { return 8 + ECDSAProvider.ECDSAPublicKeyEncodedLength + AESProvider.keyLength + ECIESProvider.authenticationTagLength; }

	@Override
	public void encode(ByteBuffer byteBuffer) throws VectorException {	
		try {
			byteBuffer.put(certID8);
			eciesProvider.encode(byteBuffer, aesEncryptionKey, encryptionPublicKey);
		} catch ( InvalidCipherTextException ex) {
			throw new VectorException("Encoding failed. Reason: " + ex.getMessage(), ex);
		}
	}

	@Override
	public RecipientInfo decode(ByteBuffer byteBuffer) {
		assert(this.certID8 != null);
		
		byte[] certID8 = new byte[8];
		byteBuffer.get(certID8);
		
		try {
			// if recipient is not me, then skip this key (by sending null to eciesProvider.decode)
			ECPrivateKeyParameters  key = Arrays.equals(this.certID8, certID8) ? encryptionPrivateKey : null;
			KeyParameter aesEncryptionKey = eciesProvider.decode(byteBuffer, key);
			return new RecipientInfo(certID8, aesEncryptionKey);
		} catch ( InvalidCipherTextException ex) {
			log.info(String.format("Decoding failed for %s. Reason: %s", Hex.encodeHexString(certID8), ex.getMessage(), ex));
			return new RecipientInfo(certID8, null);
		}
	}
	
}
