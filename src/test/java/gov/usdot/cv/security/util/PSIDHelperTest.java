package gov.usdot.cv.security.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import java.nio.ByteBuffer;

import gov.usdot.cv.security.util.UnitTestHelper;

import org.apache.commons.codec.binary.Hex;

import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

public class PSIDHelperTest {
	
	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(PSIDHelperTest.class);

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
	}

	@Test
	public void testSuccess() {
		int[][] psidLists = {
			new int[] { 0x0, 0x2, 0x5b, 0x7f, },
			new int[] { 0x80, 0x8d, 0xfff, 0x2FE0, 0x3FFF, },
			new int[] { 0x4000, 0x6789, 0x56789, 0xFFFFF, 0x100000, 0x1FFFFF, },
			new int[] { 0x200000, 0x20beef, 0xFFFFFF, 0x2345678, 0xFFFFFFF },
		};
		int length = 0;
		for ( int[] psidList : psidLists ) {
			length++;
			for ( int psid : psidList ) {
				test(psid, length, true);
			}
		}
	}
	
	
	@Test
	public void testFailure() {
		test(-1, 1, false);
		test(0xFFFFFFF + 1, 4, false);
		test(0x7FFFFFFF, 4, false);
	}
	
	private void test(int psid, int expectedLength, boolean expectedSuccess) {
		log.debug(String.format("Testing 0x%x", psid));
		
		int actualLength = PSIDHelper.calculateLength(psid);
		log.debug(String.format("Encoding length - Expected: %d, Actual: %d", expectedLength, actualLength));
		if ( expectedSuccess ) {
			assertEquals(expectedLength, actualLength);
		} else {
			assertFalse(expectedLength == actualLength);
			assertEquals(-1, actualLength);
		}
		
		ByteBuffer bb = ByteBuffer.allocate(16);
		if ( PSIDHelper.encodePSID(bb, psid) == false ) {
			String msg = String.format("Failed to encode PSID 0x%x", psid);
			log.error(msg);
			assertTrue(msg, !expectedSuccess);
			return;
		}
		assertEquals(expectedLength, bb.position());
		byte[] bytes = new byte[actualLength];
		bb.rewind();
		bb.get(bytes);
		log.debug("Encoded PSID: " + Hex.encodeHexString(bytes));
		
		bb = ByteBuffer.wrap(bytes);
		int decodedPSID = PSIDHelper.decodePSID(bb);
		log.debug(String.format("Decoding PSID - Expected: 0x%x, Actual: 0x%x", psid, decodedPSID));
		assertEquals(psid, decodedPSID);
	}

}
