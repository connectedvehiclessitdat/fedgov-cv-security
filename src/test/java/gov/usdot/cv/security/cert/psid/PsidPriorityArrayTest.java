package gov.usdot.cv.security.cert.psid;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import gov.usdot.cv.security.cert.psid.PsidPriorityArray;
import gov.usdot.cv.security.cert.psid.PsidPriorityVectorItem;
import gov.usdot.cv.security.type.ArrayType;
import gov.usdot.cv.security.util.ByteBufferHelper;
import gov.usdot.cv.security.util.UnitTestHelper;
import gov.usdot.cv.security.util.vector.VectorException;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

public class PsidPriorityArrayTest {
	
	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(PsidPriorityArrayTest.class);

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
	}

	@Test
	public void testFromIssuer() throws VectorException {
		PsidPriorityArray psidPriorityArray = new PsidPriorityArray(ArrayType.FromIssuer, null, null);
		log.debug("psidArray: " + psidPriorityArray);
		ByteBuffer byteBuffer = ByteBuffer.allocate(4096);
		PsidPriorityArray.encode(byteBuffer, psidPriorityArray);
		log.debug("FromIssuer " + Hex.encodeHexString(ByteBufferHelper.copyBytes(byteBuffer)));
		byteBuffer.rewind();
		PsidPriorityArray psidPriorityArray2 = PsidPriorityArray.decode(byteBuffer);
		assertMatch(psidPriorityArray, psidPriorityArray2);
	}

	@Test
	public void testSpecified() throws VectorException {
		Integer[][][] psidLists = {
			null,
			new Integer[][] { },
			new Integer[][] { {1, 0} },
			new Integer[][] { {1, 1}, {2, 2}, {3, 3} },
			new Integer[][] { {0x0, 5}, {0x2, 6}, {0x5b, 7}, {0x7f, 8} },
			new Integer[][] { {0x80, 0xff}, {0x8d, 0xfe}, {0xfff, 0xfd}, {0x2FE0, 0xfc}, {0x3FFF, 0xfb} },
			new Integer[][] { {0x4000, 15}, {0x6789, 16}, {0x56789, 17}, {0xFFFFF, 0xfa}, {0x100000, 0xfb}, {0x1FFFFF, 0xff} },
			new Integer[][] { {0x200000, 0xca}, {0x20beef, 0xfe}, {0xFFFFFF, 0xba}, {0x2345678, 0xbe}, {0xFFFFFFF, 0xff} },
			new Integer[][] { {0x0, 0xff}, {0x80, 0xff}, {0x4000, 0xff}, {0x200000, 0xff} },
			new Integer[][] { {0x2, 17}, {0xfff, 19}, {0xFFFFF, 257}, {0x2345678, 251}},
			new Integer[][] { {0xFFFFFF,131}, {0xFFFFF, 181}, {0xfff, 193}, {0x5b, 107}},
		};
		for(Integer[][] psidList : psidLists) {
			testSpecified(psidList);
		}
	}
	
	public void testSpecified(Integer[][] psids) throws VectorException {
		int psidsLength = psids != null ? psids.length : 0;
		List<PsidPriorityVectorItem> permissionsList = null;
		if ( psids != null ) {
			permissionsList = new ArrayList<PsidPriorityVectorItem>(psidsLength);
			for( int i = 0; i < psids.length; i++ )
				permissionsList.add(new PsidPriorityVectorItem(psids[i][0], psids[i][1]));				
		}

		PsidPriorityArray psidPriorityArray = new PsidPriorityArray(ArrayType.Specified, permissionsList, null);
		log.debug("psidArray: " + psidPriorityArray);
		ByteBuffer byteBuffer = ByteBuffer.allocate(4096);
		PsidPriorityArray.encode(byteBuffer, psidPriorityArray);
		log.debug("Specified " + Hex.encodeHexString(ByteBufferHelper.copyBytes(byteBuffer)));
		byteBuffer.rewind();
		PsidPriorityArray psidPriorityArray2 = PsidPriorityArray.decode(byteBuffer);
		assertMatch(psidPriorityArray, psidPriorityArray2);
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
		PsidPriorityArray psidPriorityArray = new PsidPriorityArray(ArrayType.Unknown, null, bytes);
		log.debug("psidArray: " + psidPriorityArray);
		ByteBuffer byteBuffer = ByteBuffer.allocate(4096);
		PsidPriorityArray.encode(byteBuffer, psidPriorityArray);
		log.debug("Unknown " + Hex.encodeHexString(ByteBufferHelper.copyBytes(byteBuffer)));
		byteBuffer.rewind();
		PsidPriorityArray psidPriorityArray2 = PsidPriorityArray.decode(byteBuffer);
		assertMatch(psidPriorityArray, psidPriorityArray2);
	}
	
	private void assertMatch(PsidPriorityArray psidPriorityArray, PsidPriorityArray psidPriorityArray2) {
		assertNotNull(psidPriorityArray);
		assertNotNull(psidPriorityArray2);
		assertEquals(psidPriorityArray.getType().getValue(), psidPriorityArray2.getType().getValue());
		switch( psidPriorityArray.getType() ) {
		case FromIssuer:
			assertNull(psidPriorityArray.getPermissionsList());
			assertNull(psidPriorityArray.getOtherPermissions());
			assertNull(psidPriorityArray2.getPermissionsList());
			assertNull(psidPriorityArray2.getOtherPermissions());
			break;
		case Specified:
			assertNull(psidPriorityArray.getOtherPermissions());
			assertNull(psidPriorityArray2.getOtherPermissions());
			assertNotNull(psidPriorityArray.getPermissionsList());
			assertNotNull(psidPriorityArray2.getPermissionsList());
			List<PsidPriorityVectorItem> list = psidPriorityArray.getPermissionsList();
			List<PsidPriorityVectorItem> list2 = psidPriorityArray2.getPermissionsList();
			assertEquals(list.size(),list2.size());
			for( int i = 0; i < list.size(); i++ ) {
				PsidPriorityVectorItem item = list.get(i);
				PsidPriorityVectorItem item2 = list2.get(i);
				assertNotNull(item);
				assertNotNull(item2);
				assertEquals(item.getPsid(), item2.getPsid());
				assertEquals(item.getMaxPriority(), item2.getMaxPriority());
			}
			break;
		case Unknown:
			assertNull(psidPriorityArray.getPermissionsList());
			assertNull(psidPriorityArray2.getPermissionsList());
			assertNotNull(psidPriorityArray.getOtherPermissions());
			assertNotNull(psidPriorityArray2.getOtherPermissions());
			assertTrue(Arrays.equals(psidPriorityArray.getOtherPermissions(), psidPriorityArray2.getOtherPermissions()));
			break;
		default:
			assertTrue("Unsupported array type", false);
		}
	}

}
