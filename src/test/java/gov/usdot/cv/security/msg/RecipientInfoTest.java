package gov.usdot.cv.security.msg;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.Arrays;

import gov.usdot.cv.security.cert.Certificate;
import gov.usdot.cv.security.cert.CertificateException;
import gov.usdot.cv.security.cert.CertificateManager;
import gov.usdot.cv.security.crypto.AESProvider;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.util.ByteBufferHelper;
import gov.usdot.cv.security.util.UnitTestHelper;
import gov.usdot.cv.security.util.vector.VectorException;

import org.apache.log4j.Logger;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

public class RecipientInfoTest {

	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(RecipientInfoTest.class);
	
	static final String testCertName = "Client";

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
		CryptoProvider.initialize();
		CertificateManager.clear();
		TestCertificateStore.load();
	}
	
	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		CertificateManager.clear();
	}
	
	@Test
	public void testUseCase() throws InvalidCipherTextException, CertificateException, VectorException {
		// sending side
		KeyParameter symmetricKey = AESProvider.generateKey();
		assertNotNull(symmetricKey);
		log.debug(Hex.toHexString(symmetricKey.getKey()));
		byte[] bytes = encode(symmetricKey);
		
		// receiving side
		KeyParameter symmetricKey2 = decode(bytes);
		assertNotNull(symmetricKey2);
		log.debug(Hex.toHexString(symmetricKey.getKey()));
		assertTrue(Arrays.equals(symmetricKey.getKey(), symmetricKey2.getKey()));
	}
	
	public byte[] encode(KeyParameter symmetricKey) throws InvalidCipherTextException, CertificateException, VectorException {		
		Certificate publicCert = CertificateManager.get(testCertName);
		assertNotNull(publicCert);
		
		byte[] certID8 = publicCert.getCertID8();
		assertNotNull(certID8);
		assertEquals(8, certID8.length);
		
		RecipientInfo recipientInfo = new RecipientInfo(new CryptoProvider(), certID8, symmetricKey);
		assertNotNull(recipientInfo);
		ByteBuffer byteBuffer = ByteBuffer.allocate(1024);
		recipientInfo.encode(byteBuffer);

		return ByteBufferHelper.copyBytes(byteBuffer);
	}
	
	public KeyParameter decode(byte[] bytes) throws InvalidCipherTextException, CertificateException, VectorException {
		Certificate privateCert = CertificateManager.get(testCertName);
		assertNotNull(privateCert);
		
		byte[] certID8 = privateCert.getCertID8();
		assertNotNull(certID8);
		assertEquals(8, certID8.length);
		
		ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
		
		RecipientInfo recipientInfo = new RecipientInfo(new CryptoProvider(), certID8);
		return recipientInfo.decode(byteBuffer).getAesEncryptionKey();
	}
}
