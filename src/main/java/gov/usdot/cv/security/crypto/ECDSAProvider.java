package gov.usdot.cv.security.crypto;

import gov.usdot.cv.security.cert.Certificate;
import gov.usdot.cv.security.type.EccPublicKeyType;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

/** 
 * Helper provider that is used to create and verify ECDSA signatures
 * 1609.2 signatures are ECDSA signatures of the SHA-256 hash of the message.
 * The resulting signature is an r-value (a random value used in generating
 * the signature) and an s-value (the resulting signature). 
 */
public class ECDSAProvider {
	
	private static final Logger log = Logger.getLogger(ECDSAProvider.class);

	/**
	 * Length of the encoded ECDSA public key in bytes
	 */
	public static final int ECDSAPublicKeyEncodedLength  = 33;
	
	/**
	 * Length of the encoded ECDSA private key in bytes
	 */
	public static final int ECDSAPrivateKeyEncodedLength = 32;
	
	private static final byte[] nullPublicKey = new byte[ECDSAPublicKeyEncodedLength];

	private final CryptoProvider cryptoProvider;
	private final ECDSASigner ecdsaSigner;
	private final ECKeyPairGenerator ecdsaKeyGenerator;
	private final ECCurve ecdsaEllipticCurve;
	private final ECDomainParameters ecdsaDomainParameters;
	
	/**
	 * Instantiates ECDSA provider with new cryptographic provider
	 */
	public ECDSAProvider() {
		this(new CryptoProvider());
	}

	/**
	 * Instantiates ECDSA provider
	 * @param cryptoProvider cryptographic provider to use
	 */
	public ECDSAProvider(CryptoProvider cryptoProvider) {
		this.cryptoProvider = cryptoProvider;
		X9ECParameters curveX9ECParameters = NISTNamedCurves.getByName("P-256");
		ecdsaEllipticCurve = curveX9ECParameters.getCurve();
		ECPoint ecdsaGenerator = curveX9ECParameters.getG();
		ecdsaDomainParameters = new ECDomainParameters(
				ecdsaEllipticCurve, ecdsaGenerator, curveX9ECParameters.getN(), curveX9ECParameters.getH());
		ECKeyGenerationParameters ecdsaKeyGenParameters = new ECKeyGenerationParameters(
				ecdsaDomainParameters, CryptoProvider.getSecureRandom());
		ecdsaKeyGenerator = new ECKeyPairGenerator();
		ecdsaKeyGenerator.init(ecdsaKeyGenParameters);
		ecdsaSigner = new ECDSASigner();
	}
	
	/**
	 * Computes message signature
	 * @param message bytes to compute a signature for
	 * @param key private signing key to use
	 * @return message signature
	 */
	public ECDSASignature computeSignature(byte[] message, ECPrivateKeyParameters key) {
		return message != null ? computeSignature(message, 0, message.length, key) : null;
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
		byte[] hashValue = cryptoProvider.computeDigest(message, start, length);
		ecdsaSigner.init(true, new ParametersWithRandom(key, CryptoProvider.getSecureRandom()));
		BigInteger[] signatureValue = ecdsaSigner.generateSignature(hashValue);
		return new ECDSASignature(signatureValue[0], signatureValue[1]);
	}

	/**
	 * Validates message signature
	 * @param message bytes to validate
	 * @param key public signing key to use
	 * @param signature to validate
	 * @return true if the signature is valid and false otherwise
	 */
	public boolean verifySignature(byte[] message, ECPublicKeyParameters key, ECDSASignature signature) {
		return message != null ? verifySignature(message, 0, message.length, key, signature) : false;
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
		byte[] hashValue = cryptoProvider.computeDigest(message, start, length);
		ecdsaSigner.init(false, key);
		return ecdsaSigner.verifySignature(hashValue, signature.r, signature.s);
	}
	
	/**
	 * Decode ECC public key. See EccPublicKey (6.2.18)
	 * @param byteBuffer buffer to decode ECC public key from
	 * @return decoded ECC public key
	 */
	public ECPublicKeyParameters decodePublicKey(ByteBuffer byteBuffer) {
		if (byteBuffer == null) {
			log.error("Invalid parameter: byteBuffer should not be null");
			return null;
		}
		int typeValue = byteBuffer.array()[byteBuffer.position()] & 0xFF;	// peek EccPublicKeyType type value
		log.debug("Public key type: " + typeValue);
		EccPublicKeyType type = EccPublicKeyType.valueOf(typeValue);
		if ( type == null ) {
			log.error(String.format("Unexpected EccPublicKeyType value %d", typeValue));
			return null;
		}
		final int bufferLength = type == EccPublicKeyType.Uncompressed ? (ECDSAPublicKeyEncodedLength*2 -1) : ECDSAPublicKeyEncodedLength;
		byte[] publicKeyBytes = new byte[bufferLength];
		byteBuffer.get(publicKeyBytes);
		return decodePublicKey(publicKeyBytes);
	}
	
	/**
	 * Decode ECC public key from bytes. See EccPublicKey (6.2.18)
	 * @param publicKeyBytes to decode ECC public key from
	 * @return decoded ECC public key
	 */
	public ECPublicKeyParameters decodePublicKey(byte[] publicKeyBytes) {
		return !Arrays.areEqual(publicKeyBytes, nullPublicKey) ?
			new ECPublicKeyParameters(ecdsaEllipticCurve.decodePoint(publicKeyBytes), ecdsaDomainParameters) : null;
	}
	
	/**
	 * Encode compressed ECC public key 
	 * @param byteBuffer buffer to encode the compressed ECC public key to
	 * @param publicKey compressed ECC public key to encode
	 * @return true if encoding was successful and false otherwise
	 */
	public boolean encodePublicKey(ByteBuffer byteBuffer, ECPublicKeyParameters publicKey) {
		if (publicKey != null) {	
			ECPoint keyValue = publicKey.getQ();			
			BigInteger xValue = keyValue.getAffineXCoord().toBigInteger();
			ECFieldElement yCoord = keyValue.getAffineYCoord();
			byteBuffer.put( (byte)(yCoord.testBitZero() ? EccPublicKeyType.CompressedLsbY1.getValue() : EccPublicKeyType.CompressedLsbY0.getValue()) );
			return ECDSASignature.encodeBigInteger(byteBuffer, xValue, ECDSAPublicKeyEncodedLength-1);
		} else {
			byteBuffer.put(nullPublicKey);
			return true;
		}
	}
	
	/**
	 * Decodes private key
	 * @param byteBuffer buffer to decode the key from
	 * @return decoded private key
	 */
	public ECPrivateKeyParameters decodePrivateKey(ByteBuffer byteBuffer) {
		byte[] privateKeyBytes = new byte[ECDSAPrivateKeyEncodedLength];
		byteBuffer.get(privateKeyBytes);
		return decodePrivateKey(privateKeyBytes);
	}
	
	/**
	 * Decodes private key
	 * @param privateKeyBytes array to decode the key from
	 * @return decoded private key
	 */
	public ECPrivateKeyParameters decodePrivateKey(byte[] privateKeyBytes) {
		return !Arrays.areEqual(privateKeyBytes,new byte[ECDSAPrivateKeyEncodedLength]) ?
				new ECPrivateKeyParameters(new BigInteger(1, privateKeyBytes), ecdsaDomainParameters) : null;
	}
	
	/**
	 * Encodes private key
	 * @param byteBuffer buffer to encode into
	 * @param privateKey private key to encode
	 * @return true if encoding succeeds and false otherwise
	 */
	public boolean encodePrivateKey(ByteBuffer byteBuffer, ECPrivateKeyParameters privateKey) {
		byte[] keyBytes;
		if (privateKey != null) {
			keyBytes = privateKey.getD().toByteArray();
			assert(keyBytes != null);
			if (keyBytes.length == ECDSAPrivateKeyEncodedLength) {
				byteBuffer.put(keyBytes);
			} else 	if (keyBytes.length == ECDSAPrivateKeyEncodedLength + 1) {
				if (keyBytes[0] != (byte)0) {
					log.error(String.format("Unexpected key bytes value of length 33.  Expected leading byte value: 0. Actual: 0x%0x.", keyBytes[0]));
					return false;
				}
				byteBuffer.put(keyBytes, 1, ECDSAPrivateKeyEncodedLength);
			} else if (keyBytes.length < ECDSAPrivateKeyEncodedLength) {
				byteBuffer.put(new byte[ECDSAPrivateKeyEncodedLength - keyBytes.length]);
				byteBuffer.put(keyBytes);
			} else {
				log.error(String.format("Unexpected key bytes length: %d.", keyBytes.length));
				return false;
			}
		} else {
			byteBuffer.put(new byte[ECDSAPrivateKeyEncodedLength]);
		}
		return true;
	}
	
	/**
	 * Reconstructs implicit public key
	 * @param caCert CA certificate used to create the reconstruction value
	 * @param certificate body bytes preceding the reconstruction value
	 * @param reconstructionKeyBytes reconstruction value
	 * @return reconstructed public key
	 */
	public ECPublicKeyParameters reconstructImplicitPublicKey(Certificate caCert, byte[] certificate, byte[] reconstructionKeyBytes ) {
    	ECPublicKeyParameters  reconstructionValue = decodePublicKey(reconstructionKeyBytes);
    	return reconstructImplicitPublicKey(caCert, certificate, reconstructionValue);
	}
	
	/**
	 * Reconstructs implicit public key
	 * @param caCert CA certificate used to create the reconstruction value
	 * @param certificate certificate body bytes preceding the reconstruction value
	 * @param reconstructionValue reconstruction value
	 * @return reconstructed public key
	 */
	public ECPublicKeyParameters reconstructImplicitPublicKey(Certificate caCert, byte[] certificate, ECPublicKeyParameters  reconstructionValue) {
		if ( caCert == null ) {
			log.error("Invalid parameter: CA certificate can not be null");
			return null;
		}   	
    	CryptoHelper cryptoHelper = new CryptoHelper(cryptoProvider);
    	byte[] caCertHash = cryptoHelper.computeDigest(caCert.getBytes());
    	
		byte[] reconstructionHashInput = new byte[caCertHash.length + certificate.length];
		System.arraycopy(caCertHash, 0, reconstructionHashInput, 0, caCertHash.length);
		System.arraycopy(certificate, 0, reconstructionHashInput, caCertHash.length, certificate.length);
		byte[] reconstructionHash = cryptoHelper.computeDigest(reconstructionHashInput);
		
		BigInteger hashValue = new BigInteger(1, reconstructionHash); 
    	
    	ECPoint publicKeyValue = reconstructionValue.getQ().multiply(hashValue).add(caCert.getSigningPublicKey().getQ());
    	return new ECPublicKeyParameters(publicKeyValue,ecdsaDomainParameters);
	}

	/**
	 * Generates a key pair
	 * @return new key pair
	 */
	public AsymmetricCipherKeyPair generateKeyPair() {
		return ecdsaKeyGenerator.generateKeyPair();
	}
}
