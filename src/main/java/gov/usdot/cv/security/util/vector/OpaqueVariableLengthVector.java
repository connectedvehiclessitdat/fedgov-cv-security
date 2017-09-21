package gov.usdot.cv.security.util.vector;

import gov.usdot.cv.security.util.PSIDHelper;

import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;

/**
 * Implements encode/decode helper methods for opaque variable length vector with variable length length
 * that is denoted in the standard like 'opaque data &gt;var&lt;'
 */
public class OpaqueVariableLengthVector {
	
	// "6.1.6.2 Variable-length vectors with variable-length length encoding"
	// defines the encoding schema that allows to encode length with value up to 2^56-1.
	// It is identical to the schema for Provider Service Identifier as defined in IEEE 1609.3
	// except that PSID is limited to a value that is no larger than 2^28.
	// Since we are dealing with UDP packets data that is limited to 2^16-1 bytes,
	// we use helper PSID class methods to perform all length operations
	
	private static String formatDataLengthError = "Data length %d exceeds maximum allowed value of %d (0x%x) for this variable length vector that has variable size length encoding.";

	/**
	 * Decodes an opaque variable length vector with variable length length
	 * @param byteBuffer buffer to decode
	 * @return decoded opaque bytes
	 * @throws VectorException if decoding fails
	 */
	static public byte[] decode(ByteBuffer byteBuffer) throws VectorException {
		try {
			int length = PSIDHelper.decodePSID(byteBuffer);
			if ( length >= 0 ) {
				byte[] bytes = new byte[length];
				byteBuffer.get(bytes);
				return bytes;
			}
		} catch ( BufferUnderflowException  ex ) {
			throw new VectorException("Couldn't decode opaque vector. Reason: " + ex.getMessage() , ex);
		}
		throw new VectorException("Couldn't decode variable length value for an opaque vector.");
	}
	
	/**
	 * Encodes an opaque variable length vector with variable length length
	 * @param byteBuffer buffer to encode into
	 * @param bytes bytes to encode
	 * @throws VectorException if encoding fails
	 */
	static public void encode(ByteBuffer byteBuffer, byte[] bytes) throws VectorException {
		if ( bytes == null )
			bytes = new byte[0];
		try {
			if ( !PSIDHelper.encodePSID(byteBuffer, bytes.length) ) 
				throw new VectorException(String.format(formatDataLengthError, bytes.length, PSIDHelper.maxPSIDValue, PSIDHelper.maxPSIDValue)); 
			byteBuffer.put(bytes);
		} catch (BufferOverflowException ex) {
			throw new VectorException("Couldn't decode opaque vector. Reason: " + ex.getMessage() , ex);
		} catch (ReadOnlyBufferException ex) {
			throw new VectorException("Couldn't decode opaque vector. Reason: " + ex.getMessage() , ex);	
		}
	}
}
