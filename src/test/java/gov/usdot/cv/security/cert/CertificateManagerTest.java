package gov.usdot.cv.security.cert;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import gov.usdot.cv.security.util.UnitTestHelper;

import org.apache.commons.codec.DecoderException;

import org.junit.BeforeClass;
import org.junit.Test;

public class CertificateManagerTest {

	static final private boolean isDebugOutput = false;
	static final int publicCert = 1;
	
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
		CertificateManager.clear();
	}

	@Test
	public void testCertificatesMap() throws DecoderException {
		final String raName = "RA";
		final String caName = "CA";
		Certificate caCert = CertificateManager.get(caName);
		assertNull(caCert);
		
		caCert = MockCertificateStore.createCertificates()[publicCert];
		
		CertificateManager.put(caName, caCert);
		caCert = CertificateManager.get(caName);
		assertNotNull(caCert);
		assertNull(CertificateManager.get(raName)); 
		
		byte[] certID8 = caCert.getCertID8();
		assertNotNull(certID8);
		Certificate caCert2 = CertificateManager.get(certID8);
		assertEquals(caCert, caCert2);
		
		CertificateManager.remove(caName);
		assertNull(CertificateManager.get(caName));
		assertNull(CertificateManager.get(certID8));
		
		CertificateManager.put(caCert);
		assertNull(CertificateManager.get(caName));
		assertNotNull(CertificateManager.get(certID8));
		
		CertificateManager.put(caName, caCert);
		assertNotNull(CertificateManager.get(caName));
		assertNotNull(CertificateManager.get(certID8));
		
		CertificateManager.remove(certID8);
		assertNotNull(CertificateManager.get(caName));
		assertNull(CertificateManager.get(certID8));
		
		CertificateManager.clear();
		assertNull(CertificateManager.get(caName));
		assertNull(CertificateManager.get(certID8));
	}
	
	@Test
	public void testRevocationList() throws DecoderException {

		Certificate caCert = MockCertificateStore.createCertificates()[publicCert];
		assertNotNull(caCert);
		
		byte[] caCertID8 = caCert.getCertID8();
		assertNotNull(caCertID8);
				
		Certificate raCert = MockCertificateStore.createCertificates()[publicCert];
		assertNotNull(raCert);
		
		byte[] raCertID8 = raCert.getCertID8();
		assertNotNull(raCertID8);
		
		assertFalse(CertificateManager.isRevoked(caCertID8));
		assertFalse(CertificateManager.isRevoked(caCert));
		assertFalse(CertificateManager.isRevoked(raCertID8));
		assertFalse(CertificateManager.isRevoked(raCert));
		
		List<byte[]> revocationList = new ArrayList<byte[]>();
		revocationList.add(raCertID8);
		CertificateManager.set(revocationList);
		
		assertFalse(CertificateManager.isRevoked(caCert));
		assertFalse(CertificateManager.isRevoked(caCertID8));
		assertTrue(CertificateManager.isRevoked(raCert));
		assertTrue(CertificateManager.isRevoked(raCertID8));
		
		revocationList.add(caCertID8);
		CertificateManager.set(revocationList);
		
		assertTrue(CertificateManager.isRevoked(caCertID8));
		assertTrue(CertificateManager.isRevoked(caCert));
		assertTrue(CertificateManager.isRevoked(raCertID8));
		assertTrue(CertificateManager.isRevoked(raCert));
		
		CertificateManager.set(null);
		
		assertFalse(CertificateManager.isRevoked(caCert));
		assertFalse(CertificateManager.isRevoked(caCertID8));
		assertFalse(CertificateManager.isRevoked(raCert));
		assertFalse(CertificateManager.isRevoked(raCertID8));
	}

}
