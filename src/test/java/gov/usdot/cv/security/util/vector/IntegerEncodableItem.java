package gov.usdot.cv.security.util.vector;

import java.nio.ByteBuffer;

/**
 * Sample encodable item implementation to be used in a vector of integers
 *
 */
class IntegerEncodableItem implements EncodableVectorItem<IntegerEncodableItem> {
	
	private int item;
	
	public IntegerEncodableItem(Integer item) {
		this.item = item != null ? item.intValue() : 0;
	}
	
	/**
	 * Retrieves payload value
	 * @return value of this encodable item
	 */
	public int get() { 
		return item; 
	}

	@Override
	public int getLength() { return 4; }

	@Override
	public void encode(ByteBuffer byteBuffer) throws VectorException {	
		try {
			byteBuffer.putInt(item);
		} catch ( Exception ex) {
			throw new VectorException("Encoding failed. Reason: " + ex.getMessage(), ex);
		}
	}

	@Override
	public IntegerEncodableItem decode(ByteBuffer byteBuffer) throws VectorException {
		try {
			return new IntegerEncodableItem(item = byteBuffer.getInt());
		} catch ( Exception ex) {
			throw new VectorException("Decoding failed. Reason: " + ex.getMessage(), ex);
		}
	}
	
}
