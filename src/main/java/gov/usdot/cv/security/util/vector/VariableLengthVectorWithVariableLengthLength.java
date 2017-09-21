package gov.usdot.cv.security.util.vector;

import gov.usdot.cv.security.util.PSIDHelper;

import java.nio.ByteBuffer;

/**
 * Implements an encodable vector per 6.1.6.2 Variable-length vectors with variable-length length encoding
 */
public abstract class VariableLengthVectorWithVariableLengthLength<T extends EncodableVectorItem<T>> extends EncodableVectorBase<T> {

	private static final long serialVersionUID = 1L;
	
	private static String formatDataLengthError = "Data length %d exceeds maximum allowed value of %d (0x%x) for this variable length vector that has variable size length encoding.";
	
	
	// "6.1.6.2 Variable-length vectors with variable-length length encoding"
	// defines the encoding schema that allows to encode length with value up to 2^56-1.
	// It is identical to the schema for Provider Service Identifier as defined in IEEE 1609.3
	// except that PSID is limited to a value that is no larger than 2^28.
	// Since we are dealing with UDP packets data that is limited to 2^16-1 bytes,
	// we use helper PSID class methods to perform all length operations

	@Override
	protected int calculateEncodedLengthLength(int dataLength) throws VectorException {
		int encodedLengthLength = PSIDHelper.calculateLength(dataLength);
		if ( encodedLengthLength < 0 )
			throw new VectorException(String.format(formatDataLengthError, dataLength, PSIDHelper.maxPSIDValue, PSIDHelper.maxPSIDValue)); 
		return encodedLengthLength;
	}

	@Override
	protected void encodeLength(ByteBuffer byteBuffer) throws VectorException {
		long dataLength = getDataLength();
		if ( dataLength > PSIDHelper.maxPSIDValue )
			throw new VectorException(String.format(formatDataLengthError, dataLength, PSIDHelper.maxPSIDValue, PSIDHelper.maxPSIDValue)); 
		PSIDHelper.encodePSID(byteBuffer, (int)dataLength);
	}

	@Override
	protected int decodeLength(ByteBuffer byteBuffer) throws VectorException {
		return PSIDHelper.decodePSID(byteBuffer);
	}
}