package gov.usdot.cv.security.msg;

import java.io.IOException;
import java.text.ParseException;

import gov.usdot.cv.security.cert.Certificate;
import gov.usdot.cv.security.cert.CertificateException;
import gov.usdot.cv.security.cert.CertificateManager;
import gov.usdot.cv.security.clock.ClockHelperTest;
import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.util.UnitTestHelper;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

public class TestCertificateStore {
	
    static final private boolean isDebugOutput = false;
    private static final Logger log = Logger.getLogger(TestCertificateStore.class);
    
	private static final String certsValidDate = "Tue Oct 14 15:20:00 EDT 2014";
    
    private static final String CaCert   = "02FF040083FF01000100041C374A82000000010102495E407595F995430B820249E71A2A21176CE7135846A5CF2C4E458424C7F8D80200031F0C0A4529071BC12144ED0E71016695F79464A855F5D85CD7863B962C1ABEB000120756A693E756D0EFD05C148FFF99A1F1F23965DEE2C7C4C0A7F795BADF17E3D863334CA409D1F9DB53766ABA0B28D1C79581F0728C57C80240EF029FD96739";
    private static final String RaCert   = "020904AF58634513BE7FFB0100834F010120041C374A82000000010103C0B9E8CB6743BBBD6A483EA2046A300671AB7B7A2D7C2AD6238D348D896D08AD020003CF4C0803B1FF6AA78B0E109837617AE5416E7B263D8245B8CD6868D6813598B9009D1D41B1EB29157C7D868120E9928A2E8190F22784EDA5AE689375E3BE3C2992743282268FDF11AAE92B7FB037FC9A0558143D15D862B0B65DCDA984F65A61D7";

	private static final String SDWCert  = "0200000001010cf2008c7b979b3d639038c83aac33b3ba3b37020bf68086d0dbab53cf3bc9f8cae7cd8e3ae2d35db06631d0a795d7172756e6766606fc77cc5015cfa2e53030f6c1033b04e9827aadbfd2fd48b8202cd9cc014d27b20224e364e6fd153e7583fb1d43e78ab80dc9a25cb7b00ed5c7b12c4ee60c1d745065d55c6849015b32f267bd802418d523195cd0b0508b7b89a88794b24dee160e53a0635a7dfcc2daa0b4e5ac777d365c6eab6f84f26c40d0dc3c0a24ea3dcaa664614483a9263f073e08549200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	private static final String SDWCertKey = "df795462330f90cd4699c5dfee92bb9c";

    private static final String BBCert  = "0200000001010cf20035cc47b1c5ca10693166fa75b3c8ea929758ebc7708f71a33fbb23791da4316ac36ac261c3059ef1b4cb1925e552ca3496187fe55c6f8245bdf49b8147992a6ba40b99f58a543adcc36497d0c31e7d0a2212042f16d4656ed916dd0c326347aa12459cb523e25707b1e072373bea947d2503913fa9bb9a66c366c02e406a417305c00674d907a577a146953ea58ead75307dc15ecb3e314e0d0cc0d7762fc448c64adeac7983461ca0868cff6e6d686c8adad68afa57e444075dad679156023d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    private static final String BBCertKey = "026560964af198001f7109e4cd27a114";
    
	public static void load() throws ParseException, DecoderException, CertificateException, IOException, CryptoException {
		CryptoProvider.initialize();
        UnitTestHelper.initLog4j(isDebugOutput);
        
		ClockHelperTest.setNow(certsValidDate);
		
		CryptoProvider cryptoProvider = new CryptoProvider();
		
		String[] names = { "CA", "RA", "Self", "Client" };
		for( String name : names )
			if ( !load(cryptoProvider, name) )
				throw new CertificateException("Couldn't load certificate named " + name);
	}
	
	public static boolean load(CryptoProvider cryptoProvider, String name) throws DecoderException, CertificateException, IOException, CryptoException {
		if ( name == null )
			return false;
		if ( name.equals("CA") )
			return load(cryptoProvider, "CA", CaCert);
		if ( name.equals("RA") )
			return load(cryptoProvider, "RA", RaCert);
		if ( name.equals("Self") )
			return load(cryptoProvider, "Self", SDWCert, SDWCertKey);
		if ( name.equals("Client") )
			return load(cryptoProvider, "Client", BBCert, BBCertKey);
		return false;
	}
	
	public static boolean load(CryptoProvider cryptoProvider, String name, String hexCert) throws DecoderException, CertificateException, IOException, CryptoException {
    	return load(cryptoProvider, name, hexCert, null);
	}
	
	public static boolean load(CryptoProvider cryptoProvider, String name, String hexCert, String hexCertKey) throws CertificateException, IOException, DecoderException, CryptoException {
    	byte[] certBytes = Hex.decodeHex(hexCert.toCharArray());
    	Certificate cert;
    	if ( hexCertKey == null ) {
    		cert = Certificate.fromBytes(cryptoProvider, certBytes);
    	} else {
	    	byte[] keyBytes = Hex.decodeHex(hexCertKey.toCharArray());
	    	cert = Certificate.fromBytes(cryptoProvider, certBytes, keyBytes);
    	}
    	if ( cert != null ) {
    		boolean isValid = cert.isValid();
    		log.debug("Certificate is valid: " + isValid);
    		if ( isValid )
    			CertificateManager.put(name, cert);
    		return isValid;
    	}
    	return false;
	}
}
