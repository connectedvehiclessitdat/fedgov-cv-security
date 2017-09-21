package gov.usdot.cv.security.util.vector;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import gov.usdot.cv.security.util.UnitTestHelper;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

public class VariableLengthVectorWithVariableLengthLengthTest {

	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(VariableLengthVectorWithVariableLengthLengthTest.class);
	
	class VariableLengthIntegerVectorWithVariableLengthLength extends VariableLengthVectorWithVariableLengthLength<IntegerEncodableItem> {
		private static final long serialVersionUID = 1L;
	}

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
	}

	@Test
	public void testIntegerVectorPositive() throws VectorException {
		testIntegerVector(1,     5); 	// encoded in 1 byte
		testIntegerVector(2,  1000);	// encoded in 2 bytes
		testIntegerVector(3,  5000);	// encoded in 3 bytes
		testIntegerVector(3, 20000);	// encoded in 3 bytes (this is more that will fit in a UDP packet)
		// the test below passes but take 15+ min to complete...
		// testIntegerVector(4524300);	// encoded in 4 bytes              
	}

	public void testIntegerVector(final int encodedLengthLength, final int count) throws VectorException {
		final int itemSize = 4;
		VariableLengthIntegerVectorWithVariableLengthLength vector = new VariableLengthIntegerVectorWithVariableLengthLength(); 
		for( int i = 0; i < count; i++ )
			vector.add( new IntegerEncodableItem(0xcafe << i*4) );
		int totalLength = vector.calculateEncodedLength();
		assertEquals(count*itemSize + encodedLengthLength, totalLength);
		ByteBuffer bb = ByteBuffer.allocate(totalLength);
		vector.encode(bb);
		bb.rewind();
		byte[] bytes = new byte[totalLength];
		bb.get(bytes);
		log.debug("Vector: " + Hex.encodeHexString(bytes));
		ByteBuffer bb2 = ByteBuffer.wrap(bytes);
		VariableLengthIntegerVectorWithVariableLengthLength vector2 = new VariableLengthIntegerVectorWithVariableLengthLength();
		vector2.decode(bb2,  new IntegerEncodableItem(0));
		assertEquals(vector.size(), vector2.size());
		for( int i = 0; i < vector2.size(); i++ ) {
			assertEquals(vector.get(i).get(), vector2.get(i).get());
			//log.debug(String.format("vector2: %08x", vector2.get(i).get()));
		}
	}

}
