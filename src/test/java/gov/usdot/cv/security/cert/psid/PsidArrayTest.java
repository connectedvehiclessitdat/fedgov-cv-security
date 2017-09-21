package gov.usdot.cv.security.cert.psid;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

import gov.usdot.cv.security.cert.psid.PsidArray;
import gov.usdot.cv.security.type.ArrayType;
import gov.usdot.cv.security.util.ByteBufferHelper;
import gov.usdot.cv.security.util.UnitTestHelper;
import gov.usdot.cv.security.util.vector.VectorException;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

public class PsidArrayTest {
	
	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(PsidArrayTest.class);

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
	}

	@Test
	public void testFromIssuer() throws VectorException {
		PsidArray psidArray = new PsidArray(ArrayType.FromIssuer, null, null);
		log.debug("psidArray: " + psidArray);
		ByteBuffer byteBuffer = ByteBuffer.allocate(4096);
		PsidArray.encode(byteBuffer, psidArray);
		log.debug("FromIssuer " + Hex.encodeHexString(ByteBufferHelper.copyBytes(byteBuffer)));
		byteBuffer.rewind();
		PsidArray psidArray2 = PsidArray.decode(byteBuffer);
		assertMatch(psidArray, psidArray2);
	}

	@Test
	public void testSpecified() throws VectorException {
		Integer[][] psidLists = {
			null,
			new Integer[] { },
			new Integer[] { 1 },
			new Integer[] { 1, 2, 3 },
			new Integer[] { 0x0, 0x2, 0x5b, 0x7f, },
			new Integer[] { 0x80, 0x8d, 0xfff, 0x2FE0, 0x3FFF, },
			new Integer[] { 0x4000, 0x6789, 0x56789, 0xFFFFF, 0x100000, 0x1FFFFF, },
			new Integer[] { 0x200000, 0x20beef, 0xFFFFFF, 0x2345678, 0xFFFFFFF },
			new Integer[] { 0x0, 0x80, 0x4000, 0x200000},
			new Integer[] { 0x2, 0xfff, 0xFFFFF, 0x2345678},
			new Integer[] { 0xFFFFFF, 0xFFFFF, 0xfff, 0x5b},
		};
		for(Integer[] psidList : psidLists) {
			testSpecified(psidList);
		}
	}
	
	public void testSpecified(Integer[] psids) throws VectorException {
		List<Integer> psidList = psids != null ? Arrays.asList(psids) : null;
		PsidArray psidArray = new PsidArray(ArrayType.Specified, psidList, null);
		log.debug("psidArray: " + psidArray);
		ByteBuffer byteBuffer = ByteBuffer.allocate(4096);
		PsidArray.encode(byteBuffer, psidArray);
		log.debug("Specified " + Hex.encodeHexString(ByteBufferHelper.copyBytes(byteBuffer)));
		byteBuffer.rewind();
		PsidArray psidArray2 = PsidArray.decode(byteBuffer);
		assertMatch(psidArray, psidArray2);
	}
	
	@Test
	public void testUnknown() throws VectorException {
		testUnknown(null);
		String[] byteStrLists = {
			"",
			"Hello, world!",
			"308203728002009A810105820420013E16830104A476A025A013800207DD81010C82010983010984011E85011E8104CE4574248204194D066F83020348820109A34A8348FFEEFEB400000064FFF9FEC800000064FFF8FE9A000000640000FEB200000064FFFBFEA8FF9C0064FFFEFEB200000064FFFBFE9C00000064FFF5FEBE00000064FFEDFEA800000064A58202E23050800420013E16A113800207DD81010C82010983010984011E85011EA2108004194D066F8104CE45742482020348A3218002E6728101688201318307000100012B000084020965A50880020104810200EC3050800420013E16A113800207DD81010C82010983010984011E85011EA2108004194D05438104CE45740E8202034AA3218002E6728101688201318307000100012B000084020965A50880020104810200EC3050800420013E16A113800207DD81010C82010983010984011E85011EA2108004194D042B8104CE45740E8202034AA3218002E6728101688201318307000100012B000084020965A50880020104810200EC3050800420013E16A113800207DD81010C82010983010984011E85011EA2108004194D02E88104CE4573FC8202034AA3218002E6728101688201318307000100012B000084020965A50880020104810200EC3050800420013E16A113800207DD81010C82010983010984011E85011EA2108004194D01BB8104CE4573FB8202034AA3218002E6728101688201318307000100012B000084020965A50880020104810200EC3050800420013E16A113800207DD81010C82010983010984011E85011EA2108004194D00858104CE4573F482020349A3218002E6728101688201318307000100012B000084020965A50880020104810200EC3050800420013E16A113800207DD81010C82010983010984011E85011DA2108004194CFF588104CE4573F382020349A3218002E6728101688201318307000100012B000084020965A50880020104810200EC3050800420013E16A113800207DD81010C82010983010984011E85011DA2108004194CFE178104CE4573EC82020349A3218002E6728101688201318307000100012B000084020965A50880020104810200EC3050800420013E16A113800207DD81010C82010983010984011E85011DA2108004194CFCF48104CE4573DF82020349A3218002E6728101688201318307000100012B000084020965A50880020104810200EC86023132",
		};
		for(String byteStr : byteStrLists) {
			testUnknown(byteStr.getBytes());
		}
	}
	
	public void testUnknown(byte[] bytes) throws VectorException {
		PsidArray psidArray = new PsidArray(ArrayType.Unknown, null, bytes);
		log.debug("psidArray: " + psidArray);
		ByteBuffer byteBuffer = ByteBuffer.allocate(4096);
		PsidArray.encode(byteBuffer, psidArray);
		log.debug("Unknown " + Hex.encodeHexString(ByteBufferHelper.copyBytes(byteBuffer)));
		byteBuffer.rewind();
		PsidArray psidArray2 = PsidArray.decode(byteBuffer);
		assertMatch(psidArray, psidArray2);
	}
	
	private void assertMatch(PsidArray psidArray, PsidArray psidArray2) {
		assertNotNull(psidArray);
		assertNotNull(psidArray2);
		assertEquals(psidArray.getType().getValue(), psidArray2.getType().getValue());
		switch( psidArray.getType() ) {
		case FromIssuer:
			assertNull(psidArray.getPermissionsList());
			assertNull(psidArray.getOtherPermissions());
			assertNull(psidArray2.getPermissionsList());
			assertNull(psidArray2.getOtherPermissions());
			break;
		case Specified:
			assertNull(psidArray.getOtherPermissions());
			assertNull(psidArray2.getOtherPermissions());
			assertNotNull(psidArray.getPermissionsList());
			assertNotNull(psidArray2.getPermissionsList());
			assertEquals(psidArray.getPermissionsList(),psidArray2.getPermissionsList());
			break;
		case Unknown:
			assertNull(psidArray.getPermissionsList());
			assertNull(psidArray2.getPermissionsList());
			assertNotNull(psidArray.getOtherPermissions());
			assertNotNull(psidArray2.getOtherPermissions());
			assertTrue(Arrays.equals(psidArray.getOtherPermissions(), psidArray2.getOtherPermissions()));
			break;
		default:
			assertTrue("Unsupported array type", false);
		}
	}

}
