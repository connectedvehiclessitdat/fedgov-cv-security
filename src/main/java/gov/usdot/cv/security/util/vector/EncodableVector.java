package gov.usdot.cv.security.util.vector;

import java.nio.ByteBuffer;

/**
 * Interface that represents a 1609.2 vector that can be encoded and decoded
 * @param <T> is a type for an item wrapped into EncodableVectorItem
 */
public interface EncodableVector<T extends EncodableVectorItem<T> > {
	
	/**
	 * Estimates number of bytes needed to store encoding of this vector.
	 * @return calculated encoded length
	 * @throws VectorException on error
	 */
	int calculateEncodedLength() throws VectorException;
	
	/**
	 * Encodes the vector
	 * @param byteBuffer buffer to encode to
	 * @throws VectorException if encoding couldn't be completed correctly
	 */
	void encode(ByteBuffer byteBuffer) throws VectorException;
	
	/**
	 * @param byteBuffer to decode from
	 * @param item dummy instance for type safe decoding
	 * @throws VectorException if encoding couldn't be completed correctly
	 */
	void decode(ByteBuffer byteBuffer, T item)  throws VectorException;
}
