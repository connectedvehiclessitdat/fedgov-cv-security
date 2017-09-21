package gov.usdot.cv.security.util.vector;

import java.nio.ByteBuffer;

/**
 * Implements 1609.2 vector as described in 6.1.5 Fixed-length vectors
 * Note that a fixed-length vector length is never encoded but rather is explicitly known to the client
 * @param <T> vectorItem
 */
public abstract class FixedLengthVector<T extends EncodableVectorItem<T>> extends EncodableVectorBase<T> {

	private static final long serialVersionUID = 1L;
	private final int fixedLength;
	
	/**
	 * Constructs a fixed-length vector
	 * @param fixedLength encoded length in octets
	 */
	public FixedLengthVector(int fixedLength) {
		this.fixedLength = fixedLength;
	}
	
	/**
	 * Always returns 0 because a fixed-length vector length is never encoded
	 * @param dataLength value to use in calculations
	 * @return always returns 0
	 */
	@Override
	protected int calculateEncodedLengthLength(int dataLength) {
		return 0;
	}
	
	/**
	 * Mandatory abstract method implementation that does nothing.
	 * @param byteBuffer to encode into
	 */
	@Override
	protected void encodeLength(ByteBuffer byteBuffer) {
	}

	/**
	 * Returns fixed length value for the vector that was provided via constructor
	 * @param byteBuffer to decode from
	 * @return decoded fixed length value for the vector
	 */
	@Override
	protected int decodeLength(ByteBuffer byteBuffer) {
		return fixedLength;
	}
}
