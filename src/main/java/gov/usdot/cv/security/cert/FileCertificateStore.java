package gov.usdot.cv.security.cert;

import gov.usdot.cv.resources.PrivateResourceLoader;
import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;

/**
 * Helper class to load a certificates stored on the file system
 *
 */
public class FileCertificateStore {
	
	private static final Logger log = Logger.getLogger(FileCertificateStore.class);
	
	/**
	 * Loads public certificate from file
	 * @param cryptoProvider cryptographic provider to use
	 * @param name friendly certificate name
	 * @param certFileName certificate file path
	 * @return true if certificate was added to the CertificateManager and false otherwise
	 * @throws DecoderException if HEX string decoding fails
	 * @throws CertificateException if certificate decoding fails
	 * @throws IOException if certificate file read fails
	 * @throws CryptoException if certificate file decryption fails
	 */
	public static boolean load(CryptoProvider cryptoProvider, String name, String certFileName) throws DecoderException, CertificateException, IOException, CryptoException {
    	return load(cryptoProvider, name, certFileName, null);
	}
	
	/**
	 * Loads encrypted certificate from file
	 * @param cryptoProvider cryptographic provider to use
	 * @param name friendly certificate name
	 * @param certFileName certificate file path
	 * @param certKeyFileName certificate decryption key file path
	 * @return true if certificate was added to the CertificateManager and false otherwise
	 * @throws DecoderException if HEX string decoding fails
	 * @throws CertificateException if certificate decoding fails
	 * @throws IOException if certificate file read fails
	 * @throws CryptoException if certificate file decryption fails
	 */
	public static boolean load(CryptoProvider cryptoProvider, String name, String certFileName, String certKeyFileName) throws CertificateException, IOException, DecoderException, CryptoException {

		byte[] certBytes = null;
		try {
			if(PrivateResourceLoader.isPrivateResource(certFileName)) {
				InputStream fileInputStream = PrivateResourceLoader.getFileAsStream(certFileName);
				
				String cleanCertFileName = PrivateResourceLoader.stripResourceIndicators(certFileName);
				boolean isBinaryFile = cleanCertFileName.toLowerCase().endsWith(".crt");
				if (isBinaryFile) {
					certBytes = IOUtils.toByteArray(fileInputStream);
				} else {
					String certString = IOUtils.toString(fileInputStream);
					certString = certString.replaceAll(" ", "");
					certBytes = Hex.decodeHex(certString.toCharArray());
				}
			}
			else {
				boolean isBinaryFile = certFileName.toLowerCase().endsWith(".crt");
				if (isBinaryFile) {
						certBytes = FileUtils.readFileToByteArray(new File(certFileName));
				} else {
					String certString = FileUtils.readFileToString(new File(certFileName));
					certString = certString.replaceAll(" ", "");
					certBytes = Hex.decodeHex(certString.toCharArray());
				}
			}
		} catch (Exception ex ) {
			log.error("Coulnd't read file '" + certFileName + "'. Reason: " + ex.getMessage(), ex);
		}
		
    	Certificate cert = null;
    	String msg = String.format("Loading certificate %s from file '%s'", name, certFileName);
    	if ( certKeyFileName == null ) {
    		cert = Certificate.fromBytes(cryptoProvider, certBytes);
    	} else {
    		msg += " using decryption key file '" +  certKeyFileName + "'";

    		try {
	    		String keyString;
	    		if(PrivateResourceLoader.isPrivateResource(certKeyFileName)) {
	    			keyString = IOUtils.toString(PrivateResourceLoader.getFileAsStream(certKeyFileName));
	    		}
	    		else {
	    			keyString = FileUtils.readFileToString(new File(certKeyFileName));
	    		}
	    		keyString = keyString.replaceAll("([,]\\s+)?0x", "");
		    	byte[] keyBytes = Hex.decodeHex(keyString.toCharArray());

		    	cert = Certificate.fromBytes(cryptoProvider, certBytes, keyBytes);
    		} catch (Exception ex ) {
    			log.error("Coulnd't read file '" + certKeyFileName + "'. Reason: " + ex.getMessage(), ex);
    		}
    	}
    	
    	if (cert != null) {
    		byte[] certId8 = cert.getCertID8();
    		assert(certId8 != null);
    		msg += ". CertId8: " + Hex.encodeHexString(certId8);
    		boolean isValid = cert.isValid();
    		msg += ". Certificate is valid: " + isValid;
    		if (isValid) {
    			CertificateManager.put(name, cert);
    		}
    		log.debug(msg);
    		return isValid;
    	}
    	
    	log.debug(msg + " was unsuccessful.");
    	return false;
	}
}
