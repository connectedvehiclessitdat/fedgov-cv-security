package gov.usdot.cv.security.cert;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import gov.usdot.cv.security.cert.CertificateTest;
import gov.usdot.cv.security.clock.ClockHelperTest;
import gov.usdot.cv.security.crypto.AESProvider;
import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.crypto.ECDSAProvider;
import gov.usdot.cv.security.crypto.ECDSASignature;
import gov.usdot.cv.security.crypto.ECIESProvider;
import gov.usdot.cv.security.util.ByteBufferHelper;
import gov.usdot.cv.security.util.UnitTestHelper;

import org.apache.commons.codec.binary.Hex;

import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

import org.apache.commons.codec.DecoderException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public class CertificateTest {

    static final private boolean isDebugOutput = false;
    private static final Logger log = Logger.getLogger(CertificateTest.class);
    
	private static final String certsValidDate = "Tue Oct 14 15:20:00 EDT 2014";
    
    private static final String CaCert   = "02FF040083FF01000100041C374A82000000010102495E407595F995430B820249E71A2A21176CE7135846A5CF2C4E458424C7F8D80200031F0C0A4529071BC12144ED0E71016695F79464A855F5D85CD7863B962C1ABEB000120756A693E756D0EFD05C148FFF99A1F1F23965DEE2C7C4C0A7F795BADF17E3D863334CA409D1F9DB53766ABA0B28D1C79581F0728C57C80240EF029FD96739";
    private static final String RaCert   = "020904AF58634513BE7FFB0100834F010120041C374A82000000010103C0B9E8CB6743BBBD6A483EA2046A300671AB7B7A2D7C2AD6238D348D896D08AD020003CF4C0803B1FF6AA78B0E109837617AE5416E7B263D8245B8CD6868D6813598B9009D1D41B1EB29157C7D868120E9928A2E8190F22784EDA5AE689375E3BE3C2992743282268FDF11AAE92B7FB037FC9A0558143D15D862B0B65DCDA984F65A61D7";
    
	private static final String SDWCert  = "0200000001010cf2008c7b979b3d639038c83aac33b3ba3b37020bf68086d0dbab53cf3bc9f8cae7cd8e3ae2d35db06631d0a795d7172756e6766606fc77cc5015cfa2e53030f6c1033b04e9827aadbfd2fd48b8202cd9cc014d27b20224e364e6fd153e7583fb1d43e78ab80dc9a25cb7b00ed5c7b12c4ee60c1d745065d55c6849015b32f267bd802418d523195cd0b0508b7b89a88794b24dee160e53a0635a7dfcc2daa0b4e5ac777d365c6eab6f84f26c40d0dc3c0a24ea3dcaa664614483a9263f073e08549200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	private static final String SDWCertKey = "df795462330f90cd4699c5dfee92bb9c";

    private static final String BBCert  = "0200000001010cf20035cc47b1c5ca10693166fa75b3c8ea929758ebc7708f71a33fbb23791da4316ac36ac261c3059ef1b4cb1925e552ca3496187fe55c6f8245bdf49b8147992a6ba40b99f58a543adcc36497d0c31e7d0a2212042f16d4656ed916dd0c326347aa12459cb523e25707b1e072373bea947d2503913fa9bb9a66c366c02e406a417305c00674d907a577a146953ea58ead75307dc15ecb3e314e0d0cc0d7762fc448c64adeac7983461ca0868cff6e6d686c8adad68afa57e444075dad679156023d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    private static final String BBCertKey = "026560964af198001f7109e4cd27a114";

    private static final String BBCertText = "030205af58634513be7ffb01000103afe1000414afd95e13a2e75e0000000102000395c75f4ae70506cfe617133fb59eee2338e2a6a7f1ebecc1fda98b56e8023e2003f06b9d5be72928e297c34f9549639d804f365f735e531950c7d56a12b5224167";
    private static final String BBCertPriE = "42b145e6b44bcb20cadf518ae7ba1e589f81c59da0b77aed2437e248548205a3";
    private static final String BBCertPriS = "e14ddad749e9915c0fd7a7b04dd28223ed175e1fbb388d9175fd888a7e5d5add";
    
    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
		CryptoProvider.initialize();
        UnitTestHelper.initLog4j(isDebugOutput);
        
		ClockHelperTest.setNow(certsValidDate);
    }
    
    @Test
    public void test()  throws DecoderException, CertificateException, IOException, CryptoException, InvalidCipherTextException {
    	testExplicit();
    	testEncrypted("Self", SDWCert, SDWCertKey, null, null, null);
    	testEncrypted("Client", BBCert, BBCertKey, BBCertText, BBCertPriE, BBCertPriS);
    }
    
    public void testExplicit() throws DecoderException, CertificateException, IOException, CryptoException {

    	final String[][] certs = {
    			{ CaCert, "CA" },
    			{ RaCert, "RA" },
    	};
    	for( String[] cert : certs)
    		test(cert[0], cert[1]);
    }
    
    public void test(String hexCert, String name) throws DecoderException, CertificateException {
    	byte[] certBytes = Hex.decodeHex(hexCert.toCharArray());
    	Certificate cert = Certificate.fromBytes(new CryptoProvider(), certBytes);
    	if ( cert != null ) {
    		boolean isValid = cert.isValid();
    		log.debug("Certificate is valid: " + isValid);
    		if ( isValid )
    			CertificateManager.put(name, cert);
    	}
    }
    
    public void testEncrypted(String name, String hexCert, String hexKey, String certText, String certPriE, String certPriS) throws DecoderException, CertificateException, IOException, CryptoException, InvalidCipherTextException {
    	CryptoProvider cryptoProvider = new CryptoProvider();
    	byte[] certBytes = Hex.decodeHex(hexCert.toCharArray());
    	byte[] keyBytes = Hex.decodeHex(hexKey.toCharArray());
    	Certificate certificate = Certificate.fromBytes(cryptoProvider, certBytes, keyBytes);
    	if ( certificate != null ) {
    		boolean isValid = certificate.isValid();
    		log.debug("Certificate is valid: " + isValid);
    		if ( isValid )
    			CertificateManager.put(name + "-private", certificate);
    		testSigningKeyPair(cryptoProvider, certificate);
    		testEncryptionKeyPair(cryptoProvider, certificate);
    		
    		if (certText != null )
    			assertTrue( "Certificate matches the one provided in details as clear text", Arrays.equals(certificate.getBytes(), Hex.decodeHex(certText.toCharArray() )));

    		ECDSAProvider ecdsaProvider = cryptoProvider.getSigner();
    		if (certPriE != null ) {
    			ECPrivateKeyParameters privateKey = certificate.getEncryptionPrivateKey();
    			ByteBuffer byteBuffer = ByteBuffer.allocate(1024);
    			ecdsaProvider.encodePrivateKey(byteBuffer, privateKey);
    			assertTrue( "Private encryption key matches the one provided in details as clear text", Arrays.equals(ByteBufferHelper.copyBytes(byteBuffer), Hex.decodeHex(certPriE.toCharArray() )));
    		}
    		
    		if (certPriS != null ) {
    			ECPrivateKeyParameters privateKey = certificate.getSigningPrivateKey();
    			ByteBuffer byteBuffer = ByteBuffer.allocate(1024);
    			ecdsaProvider.encodePrivateKey(byteBuffer, privateKey);
    			assertTrue( "Private signing key matches the one provided in details as clear text", Arrays.equals(ByteBufferHelper.copyBytes(byteBuffer), Hex.decodeHex(certPriS.toCharArray() )));
    		}
    		
			byte[] publicCertBytes = certificate.getBytes();
			Certificate publicCert = Certificate.fromBytes(cryptoProvider, publicCertBytes);
			if ( publicCert != null ) {
				assertTrue(publicCert.isValid());
				CertificateManager.put(name + "-public", certificate);
				assertNotNull(certificate.getSigningPrivateKey());
				assertNotNull(certificate.getEncryptionPrivateKey());
				assertNull(publicCert.getSigningPrivateKey());
				assertNull(publicCert.getEncryptionPrivateKey());
				comparePublicKeys(ecdsaProvider, certificate.getSigningPublicKey(), publicCert.getSigningPublicKey());
				comparePublicKeys(ecdsaProvider, certificate.getEncryptionPublicKey(), publicCert.getEncryptionPublicKey());
			}
    	}
    }
    
    private void comparePublicKeys(ECDSAProvider ecdsaProvider, ECPublicKeyParameters publicKey1, ECPublicKeyParameters publicKey2) {
		ByteBuffer byteBuffer1 = ByteBuffer.allocate(1024);
		ecdsaProvider.encodePublicKey(byteBuffer1, publicKey1);
		ByteBuffer byteBuffer2 = ByteBuffer.allocate(1024);
		ecdsaProvider.encodePublicKey(byteBuffer2, publicKey2);
		assertTrue( "Public keys match", Arrays.equals(ByteBufferHelper.copyBytes(byteBuffer1), ByteBufferHelper.copyBytes(byteBuffer2)));
    }
    
    private void testSigningKeyPair(CryptoProvider cryptoProvider, Certificate certificate) {
    	assertNotNull(cryptoProvider);
    	assertNotNull(certificate);
    	ECDSAProvider ecdsaProvider = cryptoProvider.getSigner();
    	
		final byte[] textBytes = "Hello, World!".getBytes();

		ECDSASignature signature = ecdsaProvider.computeSignature(textBytes,  certificate.getSigningPrivateKey());
		boolean isSignatureValid = ecdsaProvider.verifySignature(textBytes, certificate.getSigningPublicKey(), signature);
		log.debug("Is Signarure Valid: " + isSignatureValid);
		assertTrue(isSignatureValid);
    }
    
    public void testEncryptionKeyPair(CryptoProvider cryptoProvider, Certificate certificate) throws InvalidCipherTextException {
    	assertNotNull(cryptoProvider);
    	assertNotNull(certificate);
    	
		// generate key to encrypt
		KeyParameter symmetricKey = AESProvider.generateKey();
		assertNotNull(symmetricKey);
		log.debug(Hex.encodeHexString(symmetricKey.getKey()));
		
		// encrypt and encode the key
		ECIESProvider eciesProvider = cryptoProvider.getECIESProvider();
		
		ByteBuffer byteBuffer = ByteBuffer.allocate(1024);
		eciesProvider.encode(byteBuffer, symmetricKey, certificate.getEncryptionPublicKey());
		byte[] bytes = ByteBufferHelper.copyBytes(byteBuffer);
		
		// decode and decrypt the key
		ByteBuffer byteBuffer2 = ByteBuffer.wrap(bytes);
		KeyParameter symmetricKey2 = eciesProvider.decode(byteBuffer2, certificate.getEncryptionPrivateKey());
		assertNotNull(symmetricKey2);
		log.debug(Hex.encodeHexString(symmetricKey2.getKey()));
		
		assertTrue(Arrays.equals(symmetricKey.getKey(), symmetricKey2.getKey()));
    }
}

