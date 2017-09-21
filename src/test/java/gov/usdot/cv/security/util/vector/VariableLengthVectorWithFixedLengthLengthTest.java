package gov.usdot.cv.security.util.vector;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import gov.usdot.cv.security.util.UnitTestHelper;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

public class VariableLengthVectorWithFixedLengthLengthTest {

	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(VariableLengthVectorWithFixedLengthLengthTest.class);
	
	class VariableLengthIntegerVectorWithFixedLengthLength extends VariableLengthVectorWithFixedLengthLength<IntegerEncodableItem> {
		private static final long serialVersionUID = 1L;
		public VariableLengthIntegerVectorWithFixedLengthLength(long n) throws VectorException {
			super(n);
		}
	}

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
	}

	@Test
	public void testIntegerVectorPositive() throws VectorException {
		testIntegerVector(1,     5, true); 	// 2^8  - 1
		testIntegerVector(2,  5000, true);	// 2^16 - 1
		testIntegerVector(4, 20000, true);	// 2^32 - 1
	}
	
	@Test
	public void testIntegerVectorNegative() throws VectorException {
		testIntegerVector(1,  5000, false);	// 2^8  - 1 with more data that can be handled, failure expected
		testIntegerVector(2, 20000, false);	// 2^16 - 1 with more data that can be handled, failure expected
		// the test case below runs out of memory before it completes...
		// testIntegerVector(4, 1073741825, false);	// 2^32 - 1 with more data that can be handled, failure expected	
	}
	
	public void testIntegerVector(final int encodedLengthLength, final int count, boolean isSuccessExpected) throws VectorException {
		final int itemSize = 4;
		long n = 0;
		switch(encodedLengthLength) {
		case 1: 
			n = VariableLengthVectorWithFixedLengthLength.FixedLenghOneByte; 
			break;
		case 2: n = 
			VariableLengthVectorWithFixedLengthLength.FixedLenghTwoBytes; 
			break;
		case 4: 
			n = VariableLengthVectorWithFixedLengthLength.FixedLenghFourBytes; 
			break;
		default:
			assertTrue("Unsupport test case", false);
		}
		VariableLengthIntegerVectorWithFixedLengthLength vector = new VariableLengthIntegerVectorWithFixedLengthLength(n);
		for( int i = 0; i < count; i++ )
			vector.add( new IntegerEncodableItem(0xcafe << i*4) );
		int totalLength = vector.calculateEncodedLength();
		assertEquals(count*itemSize + encodedLengthLength, totalLength);
		ByteBuffer bb = ByteBuffer.allocate(totalLength);
		try {
			vector.encode(bb);
		} catch( VectorException ex ) {
			log.error(ex);
			if ( isSuccessExpected )
				assertTrue(ex.getMessage(), false);
			else
				return;
		}
		bb.rewind();
		byte[] bytes = new byte[totalLength];
		bb.get(bytes);
		log.debug("Vector: " + Hex.encodeHexString(bytes));
		ByteBuffer bb2 = ByteBuffer.wrap(bytes);
		VariableLengthIntegerVectorWithFixedLengthLength vector2 = new VariableLengthIntegerVectorWithFixedLengthLength(n);
		vector2.decode(bb2,  new IntegerEncodableItem(0));
		assertEquals(vector.size(), vector2.size());
		for( int i = 0; i < vector2.size(); i++ ) {
			assertEquals(vector.get(i).get(), vector2.get(i).get());
			//log.debug(String.format("vector2: %08x", vector2.get(i).get()));
		}
	}

}
