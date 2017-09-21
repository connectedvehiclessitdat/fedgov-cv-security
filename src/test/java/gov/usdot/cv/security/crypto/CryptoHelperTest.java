package gov.usdot.cv.security.crypto;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import gov.usdot.cv.security.util.UnitTestHelper;

import org.apache.log4j.Logger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.BeforeClass;
import org.junit.Test;

public class CryptoHelperTest {

	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(CryptoHelperTest.class);

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
		CryptoProvider.initialize();
	}
	
	@Test
	public void testSymmetricCipher() throws CryptoException {
		for( long i = 0; i < 1000; i++ )
			testSymmetricCipher(i);
	}
	
	public void testSymmetricCipher(long i) throws CryptoException {
		CryptoHelper helper = new CryptoHelper();
		String text = "Hello, world!";
		long started = System.currentTimeMillis();
		byte[] keyBytes = CryptoHelper.getSecureRandomBytes(16);
		KeyParameter key = new KeyParameter(keyBytes);
		byte[] nonce = CryptoHelper.getSecureRandomBytes(12);
		byte[] cipherText = helper.encryptSymmetric(key, nonce, text.getBytes());
		byte[] clearText = helper.decryptSymmetric(key, nonce, cipherText);
		long delta = System.currentTimeMillis() - started;
		if ( i == 0 )
			log.debug(new String(clearText));
		assertEquals(text, new String(clearText));
		if ( delta > 10 )
			log.debug("Symmetric encrypt/decrypt time (ms): " + delta);
		assertTrue("Symmetric encrypted/decrypted in less than 100 ms", delta < 100);
	}


	@Test
	public void testSymmetricCipher2() throws CryptoException {
		for( int i = 0; i < 3; i++ )
			testSymmetricCipher2(i);
	}
	
	public void testSymmetricCipher2(int i) throws CryptoException {
		log.debug("1 " + System.currentTimeMillis());
		CryptoProvider provider = new CryptoProvider();
		log.debug("2 " + System.currentTimeMillis());
		String text = "Hello, world!";
		log.debug("3 " + System.currentTimeMillis());
		byte[] keyBytes = CryptoHelper.getSecureRandomBytes(16);
		log.debug("4 " + System.currentTimeMillis());
		KeyParameter key = new KeyParameter(keyBytes);
		log.debug("5 " + System.currentTimeMillis());
		byte[] nonce = CryptoHelper.getSecureRandomBytes(12);
		log.debug("6 " + System.currentTimeMillis());
		AESProvider aes = provider.getSymmetricCipher();
		log.debug("7 " + System.currentTimeMillis());
		byte[] cipherText = aes.encrypt(key, nonce, text.getBytes());
		log.debug("8 " + System.currentTimeMillis());
		byte[] clearText = aes.decrypt(key, nonce, cipherText);
		log.debug("9 " + System.currentTimeMillis());
		log.debug(new String(clearText));
		assertEquals(text, new String(clearText));
	}
	
	@Test
	public void testSigner() {
		CryptoProvider provider = new CryptoProvider();
		AsymmetricCipherKeyPair keyPair = provider.getSigner().generateKeyPair();
		
		CryptoHelper helper = new CryptoHelper(provider);

		final byte[] message = "Hello, World!".getBytes();
		ECDSASignature signature = helper.computeSignature(message,  (ECPrivateKeyParameters)keyPair.getPrivate());
		boolean isSignatureValid = helper.verifySignature(message, (ECPublicKeyParameters) keyPair.getPublic(), signature);
		log.debug("Is Signarure 1 Valid: " + isSignatureValid);
		assertTrue(isSignatureValid);
		
		final byte[] message2 = "Hello, World".getBytes();
		isSignatureValid = helper.verifySignature(message2, (ECPublicKeyParameters) keyPair.getPublic(), signature);
		log.debug("Is Signarure 2 Valid: " + isSignatureValid);
		assertFalse(isSignatureValid);
		
		ByteBuffer bb = ByteBuffer.allocate(65);
		signature.encode(bb);
		bb.rewind();
		ECDSASignature signature2 = ECDSASignature.decode(bb, provider.getSigner());
		isSignatureValid = helper.verifySignature(message, (ECPublicKeyParameters) keyPair.getPublic(), signature2);
		log.debug("Is Signarure 3 Valid: " + isSignatureValid);
		assertTrue(isSignatureValid);
	}

}
