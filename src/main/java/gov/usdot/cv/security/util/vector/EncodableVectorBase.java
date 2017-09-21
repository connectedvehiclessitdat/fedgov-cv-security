package gov.usdot.cv.security.util.vector;

import java.nio.ByteBuffer;
import java.util.ArrayList;

/**
 * Abstract base class for implementing fixed and variable length 1609.2 vectors
 * @param <T> item type that implements EncodableVectorItem interface
 */
public abstract class EncodableVectorBase<T extends EncodableVectorItem<T>> extends ArrayList<T> implements EncodableVector<T> {

	private static final long serialVersionUID = 1L;
	
	// EncodableVector interface implementation
	
	@Override
	public int calculateEncodedLength() throws VectorException {
		int dataLength = (int)getDataLength();
		return calculateEncodedLengthLength(dataLength) + dataLength;
	}
	
	@Override
	public void encode(ByteBuffer byteBuffer) throws VectorException {
		encodeLength(byteBuffer);
		for( T item : this)
			item.encode(byteBuffer);
	}
	
	@Override
	public void decode(ByteBuffer byteBuffer, T item) throws VectorException {
		int length = decodeLength(byteBuffer);
		while( length > 0 ) {
			T newItem = item.decode(byteBuffer);
			add(newItem);
			length -= newItem.getLength();
		}
	}
	
	// Length encoding/decoding methods to be implemented in subclasses
	
	/**
	 * Estimates the number of octets needed to store the encoded length
	 * @param dataLength value to use in calculations
	 * @return encoded length length in octets
	 * @throws VectorException on error
	 */
	protected abstract int calculateEncodedLengthLength(int dataLength) throws VectorException;
	
	/**
	 * Encodes a length field
	 * @param byteBuffer to encode into
	 * @throws VectorException if the length couldn't be encoded successfully
	 */
	protected abstract void encodeLength(ByteBuffer byteBuffer) throws VectorException;

	/**
	 * Decodes a length field
	 * @param byteBuffer to decode from
	 * @return decoded length value
	 * @throws VectorException if the length couldn't be decoded successfully
	 */
	protected abstract int decodeLength(ByteBuffer byteBuffer) throws VectorException;
	
	// Common helper methods
	
	/**
	 * Calculates vector data length in octets
	 * @return data length
	 */
	protected long getDataLength() {
		long dataLength = 0;
		for( T item : this)
			dataLength += item.getLength();
		return dataLength;
	}

}
