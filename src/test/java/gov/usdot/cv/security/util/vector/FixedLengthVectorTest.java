package gov.usdot.cv.security.util.vector;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import gov.usdot.cv.security.util.UnitTestHelper;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

public class FixedLengthVectorTest {

	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(FixedLengthVectorTest.class);
	
	class FixedLengthIntegerVector extends FixedLengthVector<IntegerEncodableItem> {
		private static final long serialVersionUID = 1L;
		public FixedLengthIntegerVector(int fixedLength) {
			super(fixedLength);
		}
	}

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
	}

	@Test
	public void testIntegerVector() throws VectorException {
		final int count = 5;
		final int itemSize = 4;
		FixedLengthIntegerVector vector = new FixedLengthIntegerVector(count*itemSize);
		for( int i = 0; i < count; i++ )
			vector.add( new IntegerEncodableItem(0xcafe << i*4) );
		int totalLength = vector.calculateEncodedLength();
		assertEquals(count*itemSize, totalLength);
		ByteBuffer bb = ByteBuffer.allocate(totalLength);
		vector.encode(bb);
		bb.rewind();
		byte[] bytes = new byte[totalLength];
		bb.get(bytes);
		log.debug("Vector: " + Hex.encodeHexString(bytes));
		ByteBuffer bb2 = ByteBuffer.wrap(bytes);
		FixedLengthIntegerVector vector2 = new FixedLengthIntegerVector(count*itemSize);
		vector2.decode(bb2,  new IntegerEncodableItem(0));
		assertEquals(vector.size(), vector2.size());
		for( int i = 0; i < vector2.size(); i++ ) {
			assertEquals(vector.get(i).get(), vector2.get(i).get());
			log.debug(String.format("vector2: %08x", vector2.get(i).get()));
		}
	}

}
