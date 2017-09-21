package gov.usdot.cv.security.util.vector;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.Arrays;

import gov.usdot.cv.security.crypto.CryptoHelper;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.util.UnitTestHelper;

import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

public class OpaqueVariableLengthVectorTest {

	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(OpaqueVariableLengthVectorTest.class);

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
		CryptoProvider.initialize();
	}

	@Test
	public void test() throws VectorException {
		test(1,     0); // length encoded in 1 byte
		test(1,    20); // length encoded in 1 byte
		test(2,  4000);	// length encoded in 2 bytes
		test(3, 20000);	// length encoded in 3 bytes
		test(3, 80000);	// length encoded in 3 bytes (this is more that will fit in a UDP packet)
	}
	
	public void test(final int encodedLengthLength, final int length) throws VectorException {
		byte[] bytes = CryptoHelper.getSecureRandomBytes(length);
		ByteBuffer bb = ByteBuffer.allocate(encodedLengthLength + length);
		OpaqueVariableLengthVector.encode(bb, bytes);
		bb.rewind();
		byte[] bytes2 = OpaqueVariableLengthVector.decode(bb);
		assertTrue(Arrays.equals(bytes, bytes2));
	}
	
	@Test
	public void test2() throws VectorException {
		final String text = "Hello, world!";
		byte[] bytes = text.getBytes();
		ByteBuffer bb = ByteBuffer.allocate(text.length() + 4);
		OpaqueVariableLengthVector.encode(bb, bytes);
		bb.rewind();
		byte[] bytes2 = OpaqueVariableLengthVector.decode(bb);
		log.debug(new String(bytes2));
		assertTrue(Arrays.equals(bytes, bytes2));
	}

}
