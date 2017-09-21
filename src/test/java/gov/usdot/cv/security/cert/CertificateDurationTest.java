package gov.usdot.cv.security.cert;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import gov.usdot.cv.security.util.ByteBufferHelper;
import gov.usdot.cv.security.util.UnitTestHelper;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

public class CertificateDurationTest {

	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(CertificateDurationTest.class);

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
	}
	
	@Test
	public void testExplicit() {
		testExplicit(0, 1000, 0x03e8);
		testExplicit(2, 8191, 0x5fff);
	}
	
	public void testExplicit(int units, int value, int expectedEncodedValue) {
		CertificateDuration cd = new CertificateDuration((byte)units, (short)value);
		log.debug(String.format("Testing explicit units: %d, value: %d", cd.getUnits(), cd.getValue()));
		ByteBuffer bb = ByteBuffer.allocate(2);
		cd.encode(bb);
		log.debug("Encoded value: " + Hex.encodeHexString(ByteBufferHelper.copyBytes(bb)));
		bb.rewind();
		CertificateDuration cd2 = CertificateDuration.decode(bb);
		log.debug(String.format("Decoded units: %d, value: %d", cd2.getUnits(), cd2.getValue()));
		bb.rewind();
		short encodedValue = bb.getShort();
		assertEquals(expectedEncodedValue, (int)encodedValue);
	}
	
	@Test
	public void testEncodeDecode() {
		for( int units = 0; units < 5; units++ )
			for( int value=0; value <  8192; value += 17)
				testEncodeDecode((byte)units, (short)value);
	}
	
	public void testEncodeDecode(byte units, short value) {
		log.debug(String.format("Testing encode in : units %d, value: %d", units, value));
		CertificateDuration cd = new CertificateDuration(units, value);
		ByteBuffer bb = ByteBuffer.allocate(2);
		cd.encode(bb);
		bb.rewind();
		CertificateDuration cd2 = CertificateDuration.decode(bb);
		assertEquals( cd.getUnits(), cd2.getUnits() );
		assertEquals( cd.getValue(), cd2.getValue() );
		assertEquals( cd.get(), cd2.get() );
		log.debug(String.format("Testing encode out: units %d, value: %d, seconds: %d", cd2.getUnits(), cd2.getValue(), cd2.get()));
	}
	
	@Test
	public void testSeconds() {
		long[][] values = {
				// seconds  units   value
				{ 0, 				0,	0 },
				{ 1234, 			0, 	1234 },
				{ 8191, 			0,	8191 },
				{ 8192,				1, 	8192/60 },
				{ 12345,			1, 	12345/60 }, 
				{ 491460,			1,	491460/60 },
				{ 491461,			2,	491461/3600 },
				{ 1234567,			2,	1234567/3600 },
				{ 29487600,			2,	29487600/3600 },
				{ 29487601,			3,	29487601/216000 },
				{ 123456789,		3,	123456789/216000 },
				{ 1769256000,		3,	1769256000/216000 },
				{ 1769256001L,		4,	1769256001L/31556925 },
				{ 123456789012L,	4,	123456789012L/31556925 }, 
				{ 258482772675L,	4,	258482772675L/31556925 },
				{ 258482772676L,	4,	8191 },
				{ 1234567890123L,	4,	8191 },
		};
		for( long value[] : values )
			testSeconds(value[0], (byte)value[1], (short)value[2]);
	}
	
	public void testSeconds(long seconds, byte units, short value) {
		log.debug(String.format("Testing get/put: seconds: %14d, units %d, value: %12d", seconds, units, value));
		CertificateDuration cd = new CertificateDuration(seconds);
		assertEquals( units, cd.getUnits());
		assertEquals( value, cd.getValue());
		assertTrue( seconds >= cd.get());
	}

}
