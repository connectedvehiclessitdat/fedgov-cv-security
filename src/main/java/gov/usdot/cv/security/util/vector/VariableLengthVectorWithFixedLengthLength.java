package gov.usdot.cv.security.util.vector;

import java.nio.ByteBuffer;

/**
 * Implements an encodable vector per 6.1.6.1 Variable-length vectors with fixed-length length encoding
 */
public abstract class VariableLengthVectorWithFixedLengthLength<T extends EncodableVectorItem<T>> extends EncodableVectorBase<T> {

	private static final long serialVersionUID = 1L;
	
	public static final long FixedLenghOneByte    =  (1L<< 8) - 1;	// 2^8-1	-> encode length in 1 byte
	public static final long FixedLenghTwoBytes   =  (1L<<16) - 1;	// 2^16-1	-> encode length in 2 bytes
	public static final long FixedLenghFourBytes  =  (1L<<32) - 1;	// 2^32-1	-> encode length in 4 bytes
	
	private final int fixedLengthLength;
	
	/**
	 * Creates an instance of a vector with fixed-length length encoding
	 * @param n which is one of the values: 2^8-1, 2^16-1, 2^32-1, or 2^64-1 denoting that the length is encoded in one, two, four, or eight octets respectively<br>
	 * Note that due to the limitation of the UDP packet size, 2^64-1 is not supported
	 * @throws VectorException on error
	 */
	public VariableLengthVectorWithFixedLengthLength(long n)  throws VectorException {
		fixedLengthLength = 
				n == FixedLenghOneByte   ? 1 :
				n == FixedLenghTwoBytes  ? 2 :
				n == FixedLenghFourBytes ? 4 : -1;
		if ( fixedLengthLength == -1 )
			throw new VectorException(String.format("Unsupported maxLength parameter value: 0x%x (%d).", n, n));
	}
	
	@Override
	protected int calculateEncodedLengthLength(int dataLength) {
		return fixedLengthLength;
	}
	
	static final private String formatDataLengthError = "Data length %d exceeds maximum allowed value of %d for this variable length vector that has fixed size length encoding of %d byte(s).";
	
	@Override
	protected void encodeLength(ByteBuffer byteBuffer) throws VectorException {
		long dataLength = getDataLength();
		switch(fixedLengthLength) {
		case 1: 
			if( dataLength > FixedLenghOneByte )
				throw new VectorException(String.format(formatDataLengthError, dataLength, FixedLenghOneByte, fixedLengthLength));
			byteBuffer.put((byte)dataLength); 
			break;
		case 2: 
			if( dataLength > FixedLenghTwoBytes )
				throw new VectorException(String.format(formatDataLengthError, dataLength, FixedLenghTwoBytes, fixedLengthLength));
			byteBuffer.putShort((short)dataLength); 
			break;
		case 4: 
			if( dataLength > FixedLenghFourBytes )
				throw new VectorException(String.format(formatDataLengthError, dataLength, FixedLenghFourBytes, fixedLengthLength));
			byteBuffer.putInt((int)dataLength); 
			break;
		}
	}

	@Override
	protected int decodeLength(ByteBuffer byteBuffer) {
		switch(fixedLengthLength) {
		case 1: return byteBuffer.get();
		case 2: return byteBuffer.getShort();
		case 4: return byteBuffer.getInt();
		}
		return -1;
	}
}
