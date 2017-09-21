package gov.usdot.cv.security.crypto;

import gov.usdot.cv.security.type.EccPublicKeyType;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import org.apache.log4j.Logger;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * ECDSA Signature
 */
public class ECDSASignature {
	
	private static final Logger log = Logger.getLogger(ECDSASignature.class);
	
	final BigInteger r, s;
	
	/**
	 * Construct signature from r and s integers
	 * @param r r-value integer
	 * @param s s-value integer
	 */
	public ECDSASignature(BigInteger r, BigInteger s) {
		this.r = r;
		this.s = s;
	}
	
	/**
	 * Encode signature as x_coordinate_only. See EcdsaSignature (1.1.1) 
	 * @param byteBuffer signature as buffer
	 */
	public void encode(ByteBuffer byteBuffer) {
		byteBuffer.put((byte) EccPublicKeyType.XCoordinateOnly.getValue() );
		encodeBigInteger(byteBuffer, r, ECDSAProvider.ECDSAPublicKeyEncodedLength-1);
		encodeBigInteger(byteBuffer, s, ECDSAProvider.ECDSAPublicKeyEncodedLength-1);
	}
	
	/**
	 * Decode EcdsaSignature (6.2.17)<br>
	 * The signature consists of two objects.<br>
	 * The first is either an integer r or the temporary elliptic curve point R.<br>
	 * If the integer r is provided, it's encoded as an EccPublicKey with type set to x_coordinate_only.<br>
	 * If the elliptic curve point R is provided, it's encoded as an EccPublicKey with type set to compressed_lsb_y_0, compressed_lsb_y_1, or uncompressed. 
	 * The second is an integer s.
	 * @param byteBuffer to decode from
	 * @param signer signature's signer
	 * @return decoded signature instance
	 */
	static public ECDSASignature decode(ByteBuffer byteBuffer, ECDSAProvider signer) {
		int typeValue = byteBuffer.array()[byteBuffer.position()] & 0xFF;	// peek EccPublicKeyType type value
		EccPublicKeyType type = EccPublicKeyType.valueOf(typeValue);
		if ( type == null ) {
			log.error(String.format("Unexpected EccPublicKeyType value %d", typeValue));
			return null;
		}
		BigInteger r = null;
		if ( type == EccPublicKeyType.XCoordinateOnly ) {	// integer r is provided
			byteBuffer.get();								// skip type
			r = decodeBigInteger(byteBuffer, ECDSAProvider.ECDSAPublicKeyEncodedLength-1);
		} else {
			ECPublicKeyParameters publicKey = signer.decodePublicKey(byteBuffer);
			r = publicKey.getQ().getAffineXCoord().toBigInteger();
		}
		BigInteger s = decodeBigInteger(byteBuffer, ECDSAProvider.ECDSAPublicKeyEncodedLength-1);
		return new ECDSASignature(r,s);
	}

	/**
	 * Helper method for encoding integers with padding
	 * @param byteBuffer buffer to encode the value to
	 * @param value integer value to encode
	 * @param byteCount number of bytes to output
	 * @return true if encoding was successful and false otherwise
	 */
	static public boolean encodeBigInteger(ByteBuffer byteBuffer, BigInteger value, int byteCount)  {
		
		byte[] byteValue = value.toByteArray();
		if (byteValue.length > byteCount + 1) {
			log.error(String.format("Couldn't encode BigInteger value due to value overflow. Value length %d. ByteCount %d", byteValue.length, byteCount));
			return false;
		} else if (byteValue.length == byteCount + 1) {
			final int zeroByteValue = byteValue[0] & 0xFF;
			if (zeroByteValue != EccPublicKeyType.XCoordinateOnly.getValue()) {
				log.error(String.format("Couldn't encode BigInteger value due to unexpected first byte. Expected byte value 0. ByteCount %d", zeroByteValue));
				return false;
			}
			byteBuffer.put(byteValue, 1, byteCount);
		} else if (byteValue.length == byteCount) {
			byteBuffer.put(byteValue);
		} else if (byteValue.length < byteCount) {
			byteBuffer.put(new byte[byteCount - byteValue.length]);
			byteBuffer.put(byteValue);
		} else {
			return false;
		}
		return true;
	}
	
	/**
	 * Decodes an integer
	 * @param byteBuffer buffer to decode from
	 * @param byteCount max bytes to decode
	 * @return true if decoding was successful and false otherwise
	 */
	static public BigInteger decodeBigInteger(ByteBuffer byteBuffer, int byteCount) {
		byte[] bytes = new byte[byteCount];
		byteBuffer.get(bytes);
		return new BigInteger((int) 1, bytes);
	}
}