package gov.usdot.cv.security.util;

import java.nio.ByteBuffer;
import java.nio.BufferUnderflowException;

import org.apache.log4j.Logger;
import java.util.Arrays;

/**
 * Helper methods for working with ByteBuffer
 *
 */
public class ByteBufferHelper {
	
	private static final Logger log = Logger.getLogger(ByteBufferHelper.class);
	
	/**
	 * Copy all bytes from a byte buffer without disturbing it
	 * @param byteBuffer byte buffer to copy the bytes from
	 * @return bytes from the byte buffer
	 */
	static public byte[] copyBytes(ByteBuffer byteBuffer) {
		return  byteBuffer != null ? copyBytes(byteBuffer, 0, byteBuffer.position()) : null;
	}
	
	/**
	 * Copy bytes from a byte buffer without disturbing it
	 * @param byteBuffer byteBuffer byte buffer to copy the bytes from
	 * @param offset starting position for the copy operation
	 * @param length number of bytes to copy
	 * @return bytes from the byte buffer
	 */
	static public byte[] copyBytes(ByteBuffer byteBuffer, int offset, int length) throws BufferUnderflowException {
		if ( byteBuffer == null )
			return null;
		int position = byteBuffer.position();
		if ( offset + length > position) {
			log.error(String.format("Buffer is too small: current position %d, copy offset %d, copy length: %d", position, offset, length));
			throw new BufferUnderflowException();
		}
		return Arrays.copyOfRange(byteBuffer.array(), offset, offset + length);
	}
}
