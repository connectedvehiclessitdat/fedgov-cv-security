package gov.usdot.cv.security.cert;

import static org.junit.Assert.*;

import java.util.Arrays;

import gov.usdot.cv.security.cert.MockCertificateStore.MockCertificate;
import gov.usdot.cv.security.crypto.CryptoHelper;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.crypto.ECDSASignature;
import gov.usdot.cv.security.util.UnitTestHelper;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class MockCertificateStoreTest {

	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(MockCertificateStoreTest.class);

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
		CryptoProvider.initialize();
	}

	@Before
	public void setUp() throws Exception {
		MockCertificateStore.addTestCertificates();
	}

	@After
	public void tearDown() throws Exception {
		CertificateManager.clear();
	}

	@Test
	public void testCreate() {
		CryptoHelper helper = new CryptoHelper();
		
		final String caNamePrivate = "CA-private";
		Certificate caPrivateCert = CertificateManager.get(caNamePrivate);
		assertNotNull(caPrivateCert);
		ECPrivateKeyParameters caSigningPrivateKey = caPrivateCert.getSigningPrivateKey();
		assertNotNull(caSigningPrivateKey);
		
		byte[] bytes = "Hello, World".getBytes();

		ECDSASignature signature = helper.computeSignature(bytes, caSigningPrivateKey);
		assertNotNull(signature);
		
		final String caNamePublic = "CA";
		Certificate caPublicCert = CertificateManager.get(caNamePublic);
		assertNotNull(caPublicCert);
		
		ECPublicKeyParameters caSigningPublicKey = caPublicCert.getSigningPublicKey();
		assertNotNull(caSigningPublicKey);
		
		boolean isSignatureValid = helper.verifySignature(bytes, caSigningPublicKey, signature);
		log.debug("CA Signature is valid: " + isSignatureValid);
		assertTrue(isSignatureValid);
		
		final String selfNamePublic = "Self-private";
		Certificate selfPublicCert = CertificateManager.get(selfNamePublic);
		assertNotNull(caPublicCert);
		
		ECPublicKeyParameters selfSigningPublicKey = selfPublicCert.getSigningPublicKey();
		assertNotNull(selfSigningPublicKey);
		
		isSignatureValid = helper.verifySignature(bytes, selfSigningPublicKey, signature);
		log.debug("Self Signature is valid: " + isSignatureValid);
		assertFalse(isSignatureValid);
	}
	
	
	@Test
	public void testSerialize() {
		final String privateCertName = "Self-private";

		Certificate privateCert = CertificateManager.get(privateCertName);
		assertNotNull(privateCert);
		byte[] privateCertBytes = privateCert.getBytes();
		log.debug("Private Cert bytes:   " + Hex.encodeHexString(privateCertBytes));
		
		Certificate privateCert2 = MockCertificate.fromBytes(new CryptoProvider(), privateCertBytes);
		assertNotNull(privateCert2);
		byte[] privateCertBytes2 = privateCert2.getBytes();
		assertNotNull(privateCert2);
		log.debug("Private Cert 2 bytes: " + Hex.encodeHexString(privateCertBytes2));
		
		assertTrue(Arrays.equals(privateCertBytes, privateCertBytes2));

		final String publicCertName = "Self-public";
		
		Certificate publicCert = CertificateManager.get(publicCertName);
		assertNotNull(publicCert);
		byte[] publicCertBytes = publicCert.getBytes();
		log.debug("Public Cert bytes:   " + Hex.encodeHexString(publicCertBytes));
		
		Certificate publicCert2 = MockCertificate.fromBytes(new CryptoProvider(), publicCertBytes);
		assertNotNull(publicCert2);
		byte[] publicCertBytes2 = publicCert2.getBytes();
		assertNotNull(publicCert2);
		log.debug("Public Cert 2 bytes: " + Hex.encodeHexString(publicCertBytes2));
		
		assertTrue(Arrays.equals(publicCertBytes, publicCertBytes2));
		
	}

}
