package gov.usdot.cv.security.cert.psid;

import static org.junit.Assert.*;
import gov.usdot.cv.security.cert.psid.PsidSspArray;
import gov.usdot.cv.security.cert.psid.PsidSspVectorItem;
import gov.usdot.cv.security.crypto.CryptoHelper;
import gov.usdot.cv.security.type.ArrayType;
import gov.usdot.cv.security.util.ByteBufferHelper;
import gov.usdot.cv.security.util.UnitTestHelper;
import gov.usdot.cv.security.util.vector.VectorException;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

public class PsidSspArrayTest {

	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(PsidSspArrayTest.class);

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
	}

	@Test
	public void testFromIssuer() throws VectorException {
		PsidSspArray psidSspArray = new PsidSspArray(ArrayType.FromIssuer, null, null);
		log.debug("psidArray: " + psidSspArray);
		ByteBuffer byteBuffer = ByteBuffer.allocate(4096);
		PsidSspArray.encode(byteBuffer, psidSspArray);
		log.debug("FromIssuer " + Hex.encodeHexString(ByteBufferHelper.copyBytes(byteBuffer)));
		byteBuffer.rewind();
		PsidSspArray psidSspArray2 = PsidSspArray.decode(byteBuffer);
		assertMatch(psidSspArray, psidSspArray2);
	}
	
	class SpecifiedPair {
		final int psid;
		final byte[] ssp;
		SpecifiedPair(int psid, byte[] ssp) {
			this.psid = psid;
			this.ssp = ssp;
		}
	}

	@Test
	public void testSpecified() throws VectorException {
		final byte[] sspN = null,
					 sspE = new byte[0],
					 ssp1 = new byte[] { (byte)1 },
					 ssp2 = new byte[] { (byte)1, (byte)2 },
		 			 ssp8 = new byte[] { (byte)1, (byte)2, (byte)3, (byte)4, (byte)5, (byte)6, (byte)7, (byte)8 },
		 			 sspM = CryptoHelper.getSecureRandomBytes(31);

		 SpecifiedPair[][] specifiedPairs = {
				null,
				new SpecifiedPair[] { },
				new SpecifiedPair[] { new SpecifiedPair(1, null) },
				new SpecifiedPair[] { new SpecifiedPair(1, sspN), new SpecifiedPair(3, sspE), new SpecifiedPair(3, ssp1), },
				new SpecifiedPair[] { new SpecifiedPair(0x0, ssp2), new SpecifiedPair(0x2, ssp8), new SpecifiedPair(0x7f, sspM), },
				new SpecifiedPair[] { new SpecifiedPair(0x80, ssp1), new SpecifiedPair(0x8d, ssp2), new SpecifiedPair(0xfff, ssp8), new SpecifiedPair(0x2FE0, sspM), new SpecifiedPair(0x3FFF, ssp2)},
				new SpecifiedPair[] { new SpecifiedPair(0x4000, ssp8), new SpecifiedPair(0x6789, ssp1), new SpecifiedPair(0x56789, ssp2), new SpecifiedPair(0xFFFFF, sspM), new SpecifiedPair(0x100000, ssp8), new SpecifiedPair(0x1FFFFF, sspM)},
				new SpecifiedPair[] { new SpecifiedPair(0x200000, sspE), new SpecifiedPair(0x20beef, ssp8), new SpecifiedPair(0xFFFFFF, ssp1), new SpecifiedPair(0xFFFFFFF, sspM) },				
				new SpecifiedPair[] { new SpecifiedPair(0x0, sspM), new SpecifiedPair(0x80, sspM), new SpecifiedPair(0x4000, sspM), new SpecifiedPair(0x200000, sspM) },				
			};
		
		for( SpecifiedPair[] specifiedList : specifiedPairs)
			testSpecified(specifiedList);
	}
	
	public void testSpecified(SpecifiedPair[] specifiedList) throws VectorException {
		int psidsLength = specifiedList != null ? specifiedList.length : 0;
		List<PsidSspVectorItem> permissionsList = null;
		if ( specifiedList != null ) {
			permissionsList = new ArrayList<PsidSspVectorItem>(psidsLength);
			for( int i = 0; i < specifiedList.length; i++ )
				permissionsList.add(new PsidSspVectorItem(specifiedList[i].psid, specifiedList[i].ssp));				
		}

		PsidSspArray psidSspArray = new PsidSspArray(ArrayType.Specified, permissionsList, null);
		log.debug("psidArray: " + psidSspArray);
		ByteBuffer byteBuffer = ByteBuffer.allocate(4096);
		PsidSspArray.encode(byteBuffer, psidSspArray);
		log.debug("Specified " + Hex.encodeHexString(ByteBufferHelper.copyBytes(byteBuffer)));
		byteBuffer.rewind();
		PsidSspArray psidSspArray2 = PsidSspArray.decode(byteBuffer);
		assertMatch(psidSspArray, psidSspArray2);
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
		PsidSspArray psidSspArray = new PsidSspArray(ArrayType.Unknown, null, bytes);
		log.debug("psidArray: " + psidSspArray);
		ByteBuffer byteBuffer = ByteBuffer.allocate(4096);
		PsidSspArray.encode(byteBuffer, psidSspArray);
		log.debug("Unknown " + Hex.encodeHexString(ByteBufferHelper.copyBytes(byteBuffer)));
		byteBuffer.rewind();
		PsidSspArray psidSspArray2 = PsidSspArray.decode(byteBuffer);
		assertMatch(psidSspArray, psidSspArray2);
	}
	
	
	private void assertMatch(PsidSspArray psidSspArray, PsidSspArray psidSspArray2) {
		assertNotNull(psidSspArray);
		assertNotNull(psidSspArray2);
		assertEquals(psidSspArray.getType().getValue(), psidSspArray2.getType().getValue());
		switch( psidSspArray.getType() ) {
		case FromIssuer:
			assertNull(psidSspArray.getPermissionsList());
			assertNull(psidSspArray.getOtherPermissions());
			assertNull(psidSspArray2.getPermissionsList());
			assertNull(psidSspArray2.getOtherPermissions());
			break;
		case Specified:
			assertNull(psidSspArray.getOtherPermissions());
			assertNull(psidSspArray2.getOtherPermissions());
			assertNotNull(psidSspArray.getPermissionsList());
			assertNotNull(psidSspArray2.getPermissionsList());
			List<PsidSspVectorItem> list = psidSspArray.getPermissionsList();
			List<PsidSspVectorItem> list2 = psidSspArray2.getPermissionsList();
			assertEquals(list.size(),list2.size());
			for( int i = 0; i < list.size(); i++ ) {
				PsidSspVectorItem item = list.get(i);
				PsidSspVectorItem item2 = list2.get(i);
				assertNotNull(item);
				assertNotNull(item2);
				assertEquals(item.getPsid(), item2.getPsid());
				byte[] ssp = item.getSsp();
				if ( ssp != null && ssp.length == 0 )
					ssp = null;
				byte[] ssp2 = item2.getSsp();
				if ( ssp2 != null && ssp2.length == 0 )
					ssp2 = null;
				assertTrue("Items match", Arrays.equals(ssp, ssp2));
			}
			break;
		case Unknown:
			assertNull(psidSspArray.getPermissionsList());
			assertNull(psidSspArray2.getPermissionsList());
			assertNotNull(psidSspArray.getOtherPermissions());
			assertNotNull(psidSspArray2.getOtherPermissions());
			assertTrue(Arrays.equals(psidSspArray.getOtherPermissions(), psidSspArray2.getOtherPermissions()));
			break;
		default:
			assertTrue("Unsupported array type", false);
		}
	}

}
