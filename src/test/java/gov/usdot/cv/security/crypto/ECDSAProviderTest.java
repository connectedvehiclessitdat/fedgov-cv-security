package gov.usdot.cv.security.crypto;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import gov.usdot.cv.security.util.ByteBufferHelper;
import gov.usdot.cv.security.util.UnitTestHelper;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import org.junit.BeforeClass;
import org.junit.Test;

public class ECDSAProviderTest {
	
	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(ECDSAProviderTest.class);

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
		CryptoProvider.initialize();
	}

	@Test
	public void testSignature() throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
		ECDSAProvider provider =  new CryptoProvider().getSigner();
		final byte[] message = "Hello, World!".getBytes();
		AsymmetricCipherKeyPair keyPair = provider.generateKeyPair();
		ECDSASignature signature = provider.computeSignature(message,  (ECPrivateKeyParameters)keyPair.getPrivate());
		boolean isSignatureValid = provider.verifySignature(message, (ECPublicKeyParameters) keyPair.getPublic(), signature);
		log.debug("Is Signarure 1 Valid: " + isSignatureValid);
		assertTrue(isSignatureValid);
		final byte[] message2 = "Hello, World".getBytes();
		isSignatureValid = provider.verifySignature(message2, (ECPublicKeyParameters) keyPair.getPublic(), signature);
		log.debug("Is Signarure 2 Valid: " + isSignatureValid);
		assertFalse(isSignatureValid);
		
		ByteBuffer bb = ByteBuffer.allocate(65);
		signature.encode(bb);
		bb.rewind();
		ECDSASignature signature2 = ECDSASignature.decode(bb, provider);
		isSignatureValid = provider.verifySignature(message, (ECPublicKeyParameters) keyPair.getPublic(), signature2);
		log.debug("Is Signarure 3 Valid: " + isSignatureValid);
		assertTrue(isSignatureValid);
	}

	@Test
	public void testEncoding() throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
		final byte[] data = "Hello, World!".getBytes();
		
		ECDSAProvider provider = new CryptoProvider().getSigner();
		AsymmetricCipherKeyPair keyPair = provider.generateKeyPair();
		ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters)keyPair.getPrivate();
		assertNotNull("Generated private key is not null", privateKey);
		ECPublicKeyParameters  publicKey  = (ECPublicKeyParameters) keyPair.getPublic();
		assertNotNull("Generated public key is not null", publicKey);
		
		final int maxByteBuffer = (1 << 16) - 1;
		ByteBuffer privateByteBuffer = ByteBuffer.allocate(maxByteBuffer);
		provider.encodePrivateKey(privateByteBuffer, privateKey);
		byte[] privateKeyBytes = ByteBufferHelper.copyBytes(privateByteBuffer);
		log.debug("Private key size: " + privateKeyBytes.length + ". Value: " + Hex.encodeHexString(privateKeyBytes));
		ECPrivateKeyParameters privateKey2 = provider.decodePrivateKey(ByteBuffer.wrap(privateKeyBytes));
		assertNotNull("Decoded private key is not null", privateKey2);
		
		ECDSASignature signature = provider.computeSignature(data, privateKey);
		assertTrue( "Signed with original key. Signature valid with original key", provider.verifySignature(data, publicKey, signature));
		
		signature = provider.computeSignature(data, privateKey2);
		assertTrue( "Signed with decoded key. Signature valid with original key", provider.verifySignature(data, publicKey, signature));
		
		ByteBuffer publicByteBuffer = ByteBuffer.allocate(maxByteBuffer);
		assertTrue( "Public Key encoding succeeded", provider.encodePublicKey(publicByteBuffer, publicKey) );
		byte[] publicKeyBytes = ByteBufferHelper.copyBytes(publicByteBuffer);
		log.debug("Public  key size: " + publicKeyBytes.length + ". Value: " + Hex.encodeHexString(publicKeyBytes));
		ECPublicKeyParameters publicKey2 = provider.decodePublicKey(ByteBuffer.wrap(publicKeyBytes));
		assertNotNull("Decoded public key is not null", publicKey2);
		
		signature = provider.computeSignature(data, privateKey);
		assertTrue( "Signed with original key. Signature valid with original key", provider.verifySignature(data, publicKey, signature));
		assertTrue( "Signed with original key. Signature valid with decoded key", provider.verifySignature(data, publicKey2, signature));
		
		signature = provider.computeSignature(data, privateKey2);
		assertTrue( "Signed with decoded key. Signature valid with original key", provider.verifySignature(data, publicKey, signature));
		assertTrue( "Signed with decoded key. Signature valid with decoded key", provider.verifySignature(data, publicKey2, signature));
	}

}
