package gov.usdot.cv.security.cert;

import static org.junit.Assert.*;

import java.io.IOException;
import java.text.ParseException;

import gov.usdot.cv.security.clock.ClockHelperTest;
import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.crypto.ECDSAProvider;
import gov.usdot.cv.security.crypto.ECDSASignature;
import gov.usdot.cv.security.msg.TestCertificateStore;
import gov.usdot.cv.security.util.UnitTestHelper;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.junit.BeforeClass;
import org.junit.Test;

public class VehicleCertificateTest {
	
    static final private boolean isDebugOutput = false;
    private static final Logger log = Logger.getLogger(VehicleCertificateTest.class);
    
	private static final String certsValidDate = "Fri Dec 05 23:59:45 EST 2014";

    private static final String VadCert  = "030003AF58634513BE7FFB01120000059B000000009EBB361BC592B1CFAF2B0102200004148EE528014A0000000102A229680F34C0C901FC8C9B9C323DCD44F7EE30AF3E671860E81E64F859AC9A51";    
    private static final String VadCertPrivatgeSigningKey  = "1CDEBB73F9395B9F2A72E86F70B8E92D402A6568F79CFEA01E681D0F1E373972";
    
	@BeforeClass
	public static void setUpBeforeClass() throws ParseException, DecoderException, CertificateException, IOException, CryptoException {
		UnitTestHelper.initLog4j(isDebugOutput);
		CryptoProvider.initialize();
		CertificateManager.clear();
		TestCertificateStore.load();
		ClockHelperTest.setNow(certsValidDate);
	}

	@Test
	public void test() throws DecoderException, CertificateException, ParseException, IOException, CryptoException {
		CryptoProvider cryptoProvider = new CryptoProvider();
		TestCertificateStore.load(cryptoProvider, "Vad", VadCert);
		Certificate cert = CertificateManager.get("Vad");
		assertNotNull(cert);
		ECPublicKeyParameters publicSigningKey = cert.getSigningPublicKey();
		ECDSAProvider signer = cryptoProvider.getSigner();
		byte[] signingKeyBytes = Hex.decodeHex(VadCertPrivatgeSigningKey.toCharArray());
		ECPrivateKeyParameters  privateSigningKey = signer.decodePrivateKey(signingKeyBytes);
		
		final byte[] textBytes = "Hello, World!".getBytes();

		ECDSASignature signature = signer.computeSignature(textBytes,  privateSigningKey);
		boolean isSignatureValid = signer.verifySignature(textBytes, publicSigningKey, signature);
		log.debug("Is Signarure Valid: " + isSignatureValid);
		assertTrue("Signing keys match", isSignatureValid);
	}

}
