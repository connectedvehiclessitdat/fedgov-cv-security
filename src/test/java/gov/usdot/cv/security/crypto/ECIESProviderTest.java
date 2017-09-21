package gov.usdot.cv.security.crypto;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.Arrays;

import gov.usdot.cv.security.cert.Certificate;
import gov.usdot.cv.security.cert.CertificateManager;
import gov.usdot.cv.security.cert.MockCertificateStore;
import gov.usdot.cv.security.util.ByteBufferHelper;
import gov.usdot.cv.security.util.UnitTestHelper;

import org.apache.log4j.Logger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

public class ECIESProviderTest {

	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(ECIESProviderTest.class);

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
		CryptoProvider.initialize();
		MockCertificateStore.addTestCertificates();
	}
	
	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		CertificateManager.clear();
	}

	@Test
	public void testDirect() throws InvalidCipherTextException {
		CryptoProvider cryptoProvider = new CryptoProvider();
		ECIESProvider eciesProvider = new ECIESProvider(cryptoProvider);
		ByteBuffer byteBuffer = ByteBuffer.allocate(1024);
		KeyParameter symmetricKey = AESProvider.generateKey();
		assertNotNull(symmetricKey);
		log.debug(Hex.toHexString(symmetricKey.getKey()));
		AsymmetricCipherKeyPair recipientECCKey = cryptoProvider.getSigner().generateKeyPair();
		eciesProvider.encode(byteBuffer, symmetricKey, (ECPublicKeyParameters) recipientECCKey.getPublic());
		log.debug(Hex.toHexString(ByteBufferHelper.copyBytes(byteBuffer)));
		byteBuffer.rewind();
		KeyParameter symmetricKey2 = eciesProvider.decode(byteBuffer, (ECPrivateKeyParameters) recipientECCKey.getPrivate());
		assertNotNull(symmetricKey2);
		log.debug(Hex.toHexString(symmetricKey2.getKey()));
		assertTrue(Arrays.equals(symmetricKey.getKey(), symmetricKey2.getKey()));
	}
	
	@Test
	public void testUseCase() throws InvalidCipherTextException {
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
	
	public byte[] encode(KeyParameter symmetricKey) throws InvalidCipherTextException {
		final String clientCertName = "Client-public";
		Certificate publicCert = CertificateManager.get(clientCertName);
		assertNotNull(publicCert);
		
		ECIESProvider eciesProvider = new CryptoProvider().getECIESProvider();
		ByteBuffer byteBuffer = ByteBuffer.allocate(1024);

		eciesProvider.encode(byteBuffer, symmetricKey, publicCert.getEncryptionPublicKey());
		return ByteBufferHelper.copyBytes(byteBuffer);
	}
	
	public KeyParameter decode(byte[] bytes) throws InvalidCipherTextException {
		final String clientCertName = "Client-private";
		Certificate privateCert = CertificateManager.get(clientCertName);
		assertNotNull(privateCert);
		
		ECIESProvider eciesProvider = new CryptoProvider().getECIESProvider();
		ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
		
		assertNotNull(privateCert.getEncryptionPrivateKey());
		return eciesProvider.decode(byteBuffer, privateCert.getEncryptionPrivateKey());
	}
}
