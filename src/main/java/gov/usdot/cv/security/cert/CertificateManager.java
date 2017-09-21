package gov.usdot.cv.security.cert;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.math.BigInteger;

/**
 * Process wide certificate manager
 *
 */
public final class CertificateManager {
	
	private static final int initialCapacity = 16;
	private static final float loadFactor = 0.9f;
	private static final int concurrencyLevel = 1; // let's keep it simple until we have some benchmarks with real loads
	
	// we want to be able to key on friendly certificate String name (i.e. CA, RA, Self, etc.) as well as BigInteger digest
	private static final ConcurrentHashMap<Object, Certificate> certificates = new ConcurrentHashMap<Object, Certificate>(initialCapacity, loadFactor, concurrencyLevel);

	private static final Set<BigInteger> revocationList = Collections.newSetFromMap(new ConcurrentHashMap<BigInteger,Boolean>(initialCapacity, loadFactor, concurrencyLevel));
	
	/**
	 * Register the certificate with the certificate manager
	 * @param certificate to register
	 */
	public static void put(Certificate certificate) {
		assert(certificate != null);
		certificates.put(new BigInteger(certificate.getCertID8()), certificate);
	}
	
	/**
	 * Register the certificate with the certificate manager using friendly name
	 * @param name of the certificate to register
	 * @param certificate  to register
	 */
	public static void put(String name, Certificate certificate) {
		assert(name != null && certificate != null);
		certificates.put(name, certificate);
		put(certificate);
	}
	
	/**
	 * Register the certificate with the certificate manager if it is not already registered
	 * @param certID8  digest of the certificate to check
	 * @param certificate to register
	 */
	public static synchronized void put(byte[] certID8, Certificate certificate) {
		if ( CertificateManager.get(certID8) == null )
			CertificateManager.put(certificate);
	}
	
	/**
	 * Retrieves a certificate by digest
	 * @param certID8 digest of the certificate to retrieve
	 * @return the certificate specified by digest or null if one is not found
	 */
	public static Certificate get(byte[] certID8) {
		assert(certID8 != null);
		return certificates.get(new BigInteger(certID8));
	}
	
	/**
	 * Retrieves a certificate by friendly name
	 * @param name of the certificate to
	 * @return the certificate specified by digest or null if one is not found
	 */
	public static Certificate get(String name) {
		assert(name != null);
		return certificates.get(name);
	}
	
	/**
	 * Removes a certificate by digest
	 * @param certID8 digest of the certificate to remove
	 */
	public static void remove(byte[] certID8) {
		assert(certID8 != null);
		certificates.remove(new BigInteger(certID8));
	}
	
	/**
	 * Removes a certificate by friendly name
	 * @param name of the certificate to remove
	 */
	public static void remove(String name) {
		assert(name != null);
		Certificate certificate = certificates.remove(name);
		if ( certificate != null ) 
			certificates.remove(new BigInteger(certificate.getCertID8()));
	}
	
	/**
	 * Unregister all certificates
	 */
	public static void clear() {
		certificates.clear();
	}
	
	/**
	 * Assign new revocation list or null to clear the list
	 * @param newRevocationList a list of cerdID8 of the certificates that have been revoked
	 */
	public static void set(List<byte[]> newRevocationList) {
		revocationList.clear();
		if ( newRevocationList == null )
			return;
		List<BigInteger> intRevocationList = new ArrayList<BigInteger>(newRevocationList.size());
		for( byte[] digest : newRevocationList )
			intRevocationList.add(new BigInteger(digest) );
		revocationList.addAll(intRevocationList);
	}
	
	/**
	 * Verifies whether a certificate has been revoked
	 * @param certificate of interest
	 * @return true if the certificate has been revoked and false otherwise
	 */
	public static boolean isRevoked(Certificate certificate) {
		return certificate != null ? isRevoked(certificate.getCertID8()) : false;
	}
	
	/**
	 * Verifies whether a certificate with the specified digest has been revoked
	 * @param credID8 digest of the certificate of interest
	 * @return true if the certificate has been revoked and false otherwise
	 */
	public static boolean isRevoked(byte[] credID8) {
		return credID8 != null ? revocationList.contains(new BigInteger(credID8)) : false;
	}

}
