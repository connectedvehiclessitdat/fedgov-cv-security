package gov.usdot.cv.security.util.vector;

import java.nio.ByteBuffer;

/**
 * Encodable vector item to be used with encodable vector.
 * @param <T> Actual type of the implementation.
 */
public interface EncodableVectorItem<T>  {

	/**
	 * Retrieves encoded length of the item in octets
	 * @return encoded length of the item
	 */
	int getLength();
	
	/**
	 * Encodes the item into the provided buffer
	 * @param byteBuffer buffer to encode into
	 * @throws VectorException if the encoding fails
	 */
	void encode(ByteBuffer byteBuffer) throws VectorException;
	
	/**
	 * Creates a NEW instance of type T from the buffer.
	 * This really should be a static method but we are not using Java 8 yet so those are not possible.
	 * Thus, always return a new instance from this method and never 'this'.
	 * @param byteBuffer that contains encoded T bytes
	 * @return new instance decoded from the buffer
	 * @throws VectorException if the decoding fails
	 */
	T decode(ByteBuffer byteBuffer) throws VectorException;
}
