package gov.usdot.cv.security.cert;

import gov.usdot.cv.security.cert.psid.PsidArray;
import gov.usdot.cv.security.cert.psid.PsidPriorityArray;
import gov.usdot.cv.security.cert.psid.PsidSspArray;
import gov.usdot.cv.security.cert.region.GeographicRegion;
import gov.usdot.cv.security.clock.ClockHelper;
import gov.usdot.cv.security.crypto.AESProvider;
import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoHelper;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.crypto.ECDSAProvider;
import gov.usdot.cv.security.crypto.ECDSASignature;
import gov.usdot.cv.security.type.CertificateContentFlags;
import gov.usdot.cv.security.type.SubjectType;
import gov.usdot.cv.security.type.SignatureAlgorithm;
import gov.usdot.cv.security.type.SubjectTypeFlags;
import gov.usdot.cv.security.util.ByteBufferHelper;
import gov.usdot.cv.security.util.PSIDHelper;
import gov.usdot.cv.security.util.Time32Helper;
import gov.usdot.cv.security.util.vector.OpaqueVariableLengthVector;
import gov.usdot.cv.security.util.vector.VectorException;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Date;
import java.util.EnumSet;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * IEEE P1609.2/D9.3 Certificate (6.3.1)
 */
public class Certificate {
	
	private static final Logger log = Logger.getLogger(Certificate.class);
	
	protected ECPublicKeyParameters encryptionPublicKey;
	protected ECPrivateKeyParameters encryptionPrivateKey;
	protected ECPublicKeyParameters signingPublicKey;
	protected ECPrivateKeyParameters signingPrivateKey;
	protected Date expiration;
	protected Date startValidity;
	protected byte[] bytes;
	
	static private String rootPublicCertificateFriendlyName = "CA";

	static private final byte explicitCertificateVersionAndType = 2;
	static private final byte implicitCertificateVersionAndType = 3;
	
	protected final CryptoProvider cryptoProvider;
	protected final CryptoHelper cryptoHelper;
	
	private static Certificate rootPublicCertificate;

	/**
	 * Instantiates empty certificate with new cryptographic provider
	 */
	protected Certificate() {
		this(null);
	}
	
	/**
	 * Instantiates empty certificate
	 * @param cryptoProvider cryptographic provider to use
	 */
	protected Certificate(CryptoProvider cryptoProvider) {
		if ( cryptoProvider == null  )
			cryptoProvider = new CryptoProvider();
		this.cryptoProvider = cryptoProvider;
		this.cryptoHelper = new CryptoHelper(cryptoProvider);
	}
	
	/**
	 * Instantiates encoded certificate
	 * @param cryptoProvider cryptographic provider to use
	 * @param byteBuffer buffer to decode certificate from
	 * @throws CertificateException if decoding fails
	 */
	protected Certificate(CryptoProvider cryptoProvider, ByteBuffer byteBuffer) throws CertificateException {
		this(cryptoProvider);
		try {
			decode(byteBuffer);
		} catch ( VectorException ex) {
			throw new CertificateException("Certificate bytes deconid failed. Reason: " + ex.getMessage(), ex);
		}
	}
	
	/**
	 * Creates public certificate from encoded byte array
	 * @param cryptoProvider cryptographic provider to use
	 * @param bytes byte array to decode certificate from
	 * @return decoded certificate
	 * @throws CertificateException if decoding fails
	 */
	static public Certificate fromBytes(CryptoProvider cryptoProvider, byte[] bytes) throws CertificateException {
		return fromBytes(cryptoProvider, ByteBuffer.wrap(bytes));
	}
	
	/**
	 * Creates public certificate from encoded byte buffer
	 * @param cryptoProvider cryptographic provider to use
	 * @param byteBuffer byte buffer to decode certificate from
	 * @return decoded certificate
	 * @throws CertificateException if decoding fails
	 */
	static public Certificate fromBytes(CryptoProvider cryptoProvider, ByteBuffer byteBuffer) throws CertificateException {
		return new Certificate(cryptoProvider, byteBuffer);
	}
	
	/**
	 * Creates full certificate from encrypted byte buffer. Full certificate is a certificate 
	 * that contains both public and private keys but getBytes() returns only public certificate
	 * @param cryptoProvider cryptographic provider to use
	 * @param certificateBytes encrypted certificate bytes
	 * @param decryptionKey decryption key bytes
	 * @return decrypted certificate
	 * @throws CertificateException if decoding fails
	 * @throws DecoderException if HEX decoding fails (used for debug logging)
	 * @throws CryptoException if decryption fails
	 */
	static public Certificate fromBytes(CryptoProvider cryptoProvider, byte[] certificateBytes, byte[] decryptionKey) throws CertificateException, DecoderException, CryptoException {
		return fromBytes(cryptoProvider, ByteBuffer.wrap(certificateBytes), decryptionKey);
	}
	
	/**
	 * Creates full certificate from encrypted byte buffer. Full certificate is a certificate 
	 * that contains both public and private keys but getBytes() returns only public certificate
	 * @param cryptoProvider cryptographic provider to use
	 * @param certificateByteBuffer encrypted certificate byte buffer
	 * @param decryptionKey decryption key bytes
	 * @return decrypted certificate
	 * @throws CertificateException if decoding fails
	 * @throws DecoderException if HEX decoding fails (used for debug logging)
	 * @throws CryptoException if decryption fails
	 */
	static public Certificate fromBytes(CryptoProvider cryptoProvider, ByteBuffer certificateByteBuffer, byte[] decryptionKey) throws CertificateException, DecoderException, CryptoException {
		return decrypt(cryptoProvider, certificateByteBuffer, decryptionKey);
	}
	
	/**
	 * Retrieves certificate bytes that can be decoded into a public certificate
	 * @return the certificate bytes
	 */
	public byte[] getBytes() {
		return bytes;
	}

	/**
	 * Retrieves public encryption key
	 * @return public encryption key or null if the key is not present in the certificate
	 */
	public final ECPublicKeyParameters getEncryptionPublicKey() {
		return encryptionPublicKey;
	}
	
	/**
	 * Assigns new public encryption key
	 * @param encryptionPublicKey public encryption key value
	 */
	public void setEncryptionPublicKey(ECPublicKeyParameters encryptionPublicKey) {
		this.encryptionPublicKey = encryptionPublicKey;
	}

	/**
	 * Retrieves private encryption key
	 * @return private encryption key or null if the key is not present in the certificate
	 */
	public final ECPrivateKeyParameters getEncryptionPrivateKey() {
		return encryptionPrivateKey;
	}
	
	/**
	 * Assigns new private encryption key
	 * @param encryptionPrivateKey new private encryption key value
	 */
	public void setEncryptionPrivateKey(ECPrivateKeyParameters encryptionPrivateKey) {
		this.encryptionPrivateKey = encryptionPrivateKey;
	}

	/**
	 * Retrieves public signing key
	 * @return public signing key or null if the key is not present in the certificate
	 */
	public final ECPublicKeyParameters getSigningPublicKey() {
		return signingPublicKey;
	}
	
	/**
	 * Assigns new public signing key
	 * @param signingPublicKey new public signing key value
	 */
	public void setSigningPublicKey(ECPublicKeyParameters signingPublicKey) {
		this.signingPublicKey = signingPublicKey;
	}

	/**
	 * Retrieves private signing key
	 * @return private signing key or null if the key is not present in the certificate
	 */
	public final ECPrivateKeyParameters getSigningPrivateKey() {
		return signingPrivateKey;
	}

	/**
	 * Assigns new private signing key
	 * @param signingPrivateKey new private signing key value
	 */
	public void setSigningPrivateKey(ECPrivateKeyParameters signingPrivateKey) {
		this.signingPrivateKey = signingPrivateKey;
		
	}

	/**
	 * Verifies that certificate is valid i.e. state date is valid, not expired, and not revoked
	 * @return true if the certificate is valid and false otherwise
	 */
	public boolean isValid() {
		Date now = ClockHelper.nowDate();
		// start date is valid
		if ( startValidity != null && !startValidity.before(now) ) {
			log.info(String.format("The certificate will become valid on %s", startValidity));
			return false;
		}
		// not expired
		if ( !expiration.after(now) ) {
			log.error("The certificate had expired on " + expiration);
			return false;
		}
		// not revoked
		if ( CertificateManager.isRevoked(this) ) {
			log.error("The certificate was revoked");
			return false;
		}
		return true;
	}

	/**
	 * Retrieves expiration date for the certificate
	 * @return expiration date
	 */
	public Date getExpiration() {
		return expiration;
	}

	/**
	 * Retrieves certificate CertId8 (aka digest) which is
	 * the low-order 8 octets of the hash of that certificate obtained using SHA-256 as specified in the FIPS 180-3 
	 * @return 8 bytes certificate digest
	 */
	public byte[] getCertID8() {
		byte[] bytes = getBytes();
		if ( bytes == null )
			return null;
		byte[] digest = cryptoHelper.computeDigest(bytes);
		if ( digest == null )
			return null;
		byte[] certID8 = new byte[8];
		System.arraycopy(digest,  digest.length - 8, certID8, 0, 8);
		return certID8;
	}
	
	/**
	 * Returns HEX representation of the certificate bytes
	 */
	@Override
	public String toString() {
		return Hex.encodeHexString(getBytes());
	}
	
	/**
	 * Decodes certificate
	 * @param byteBuffer buffer to decode from
	 * @throws CertificateException if decoding fails
	 * @throws VectorException if vector decoding fails
	 */
	private void decode(ByteBuffer byteBuffer) throws CertificateException, VectorException {
		int startPosition = byteBuffer.position();
		// uint8 version_and_type;
		byte versionAndType = byteBuffer.get();
		if ( versionAndType != explicitCertificateVersionAndType && versionAndType != implicitCertificateVersionAndType  )
			throw new CertificateException(String.format("Unexpected certificate version and type value %d. Supported values are: %d (explicit) and %d(implicit).", 
					versionAndType, explicitCertificateVersionAndType, implicitCertificateVersionAndType));
		// ToBeSignedCertificate
		// SubjectType subject_type;
		int subjectTypeValue = byteBuffer.get() & 0xFF;
		SubjectType subjectType = SubjectType.valueOf(subjectTypeValue);
		if ( subjectType == null )
			throw new CertificateException("Unexpected subject type value: " + subjectTypeValue);
		// CertificateContentFlags cf; flags are encoded like PSIDs
		int contentFlagsValue = PSIDHelper.decodePSID(byteBuffer);
		EnumSet<CertificateContentFlags> contentFlags = CertificateContentFlags.create(contentFlagsValue);
		// CertId8 signer_id;
		byte[] signerCertId8 = null;
		// PKAlgorithm signature_alg;
		SignatureAlgorithm signatureAlgorithm = null;
		if ( subjectType != SubjectType.rootCa ) {
			signerCertId8 = new byte[8];
			byteBuffer.get(signerCertId8);
			log.debug("Signer CertId8: " + Hex.encodeHexString(signerCertId8));
			int signatureAlgValue = byteBuffer.get() & 0xFF;
			signatureAlgorithm = SignatureAlgorithm.valueOf(signatureAlgValue);
			if ( signatureAlgorithm == null )
				throw new CertificateException("Unexpected signature algorithm value: " + signatureAlgValue);	
			log.debug(String.format("signature Algorithm: %s (%d)", signatureAlgorithm.name(), signatureAlgorithm.getValue()));
		}
		// CertSpecificData scope;
		decodeCertSpecificData(byteBuffer, subjectType, contentFlags);
		
		// Time32 expiration; if 0 the certificate does not expire
		int expirationTime32 = byteBuffer.getInt();
		expiration = expirationTime32 != 0 ? Time32Helper.time32ToDate(expirationTime32) : new Date(Long.MAX_VALUE);
		Date now = ClockHelper.nowDate();
		if ( expiration.before(now) ) {
			log.error(String.format("The certificate had expired on %s", expiration));
			throw new CertificateException(String.format("The certificate had expired on %s", expiration));
		}
		if ( contentFlags.contains(CertificateContentFlags.useStartValidity) ) {
			if ( contentFlags.contains(CertificateContentFlags.lifetimeIsDuration) ) {
				// CertificateDuration lifetime; (expiration - lifetime)
				CertificateDuration lifetime = CertificateDuration.decode(byteBuffer);
				startValidity = new Date(expiration.getTime() - lifetime.get()*1000);
			} else {
				// Time32 start_validity;
				int startValidity = byteBuffer.getInt();
				this.startValidity = Time32Helper.time32ToDate(startValidity);
			}
		}
		
		// CrlSeries crl_series;
		int crlSeries = byteBuffer.getInt();
		log.debug("CrlSeries: " + crlSeries);
		
		ECDSAProvider ecdsaProvider = this.cryptoProvider.getSigner();
		
		if ( versionAndType == explicitCertificateVersionAndType ) {
			// PublicKey verification_key;
			signingPublicKey = decodePublicKey(byteBuffer, ecdsaProvider);
		}
		
		if ( contentFlags.contains(CertificateContentFlags.encryptionKey) ) {
			// PublicKey encryption_key;
			encryptionPublicKey = decodePublicKey(byteBuffer, ecdsaProvider);
		} else if ( !contentFlags.contains(CertificateContentFlags.useStartValidity) ) {
			// opaque other_cert_content<var>;
			byte[] otherCertContent = OpaqueVariableLengthVector.decode(byteBuffer);
			log.info("Ignoring Unexpected certificate content: " + Hex.encodeHexString(otherCertContent));
		}
		
		if ( versionAndType == implicitCertificateVersionAndType ) {
			ECPublicKeyParameters reconstructionValue = ecdsaProvider.decodePublicKey(byteBuffer);
			int endOfCertificate = byteBuffer.position();
			bytes = ByteBufferHelper.copyBytes(byteBuffer, startPosition, endOfCertificate - startPosition);
			signingPublicKey = ecdsaProvider.reconstructImplicitPublicKey(getSignerCertificate(signerCertId8), bytes, reconstructionValue );
		} else {
			assert(versionAndType == explicitCertificateVersionAndType);
			// End of unsigned data
			int endOfUnsignedData = byteBuffer.position();
	
			// Decode and validate signature
			ECDSASignature signature = ECDSASignature.decode(byteBuffer, cryptoProvider.getSigner());
			
			// Decode and verify signature
			ECPublicKeyParameters signingKey = null;

			Certificate signerCertificate = getSignerCertificate(signerCertId8);
			if ( signerCertificate != null )
				signingKey = signerCertificate.getSigningPublicKey();
			if ( signingKey == null ) {
				if ( subjectType == SubjectType.rootCa )
					signingKey = this.signingPublicKey;
				else
					throw new CertificateException("Couldn't get root public certificate public signing key. Make sure that certificate store is properly initialized");
			}
			if ( !cryptoHelper.verifySignature(byteBuffer.array(), startPosition, endOfUnsignedData, signingKey, signature) ) {
				throw new CertificateException("Certificate signature is not valid");
			}
			int endOfCertificate = byteBuffer.position();
			bytes = ByteBufferHelper.copyBytes(byteBuffer, startPosition, endOfCertificate - startPosition);
		}
	}
	
	/**
	 * Decodes public key
	 * @param byteBuffer buffer to decode from
	 * @param ecdsaProvider ECDSA provider to use for decoding
	 * @return decoded public key
	 * @throws CertificateException if decoding fails
	 * @throws VectorException if decoding fails
	 */
	private ECPublicKeyParameters decodePublicKey(ByteBuffer byteBuffer, ECDSAProvider ecdsaProvider) throws CertificateException, VectorException {
		// PKAlgorithm algorithm;
		int algorithmValue = byteBuffer.get() & 0xFF;
		SignatureAlgorithm algorithm = SignatureAlgorithm.valueOf(algorithmValue);
		if ( algorithm == null )
			throw new CertificateException("Unexpected public key algorithm value: " + algorithm);
		if ( algorithm == SignatureAlgorithm.EciesNistp256 ) {
			// SymmAlgorithm supported_symm_alg;
			byte supportedSymmAlg = byteBuffer.get();
			if ( supportedSymmAlg != 0 )
				log.warn("Ignoring unsupported symmetric algorithm: " + supportedSymmAlg);
		}
		// EccPublicKey public_key;
		return ecdsaProvider.decodePublicKey(byteBuffer);
	}

	/**
	 * Decodes CertSpecificData
	 * @param byteBuffer buffer to decode from
	 * @param subjectType subject type
	 * @param contentFlags content flags
	 * @throws VectorException if decoding fails
	 * @throws CertificateException if decoding fails
	 */
	private void decodeCertSpecificData(ByteBuffer byteBuffer, SubjectType subjectType, EnumSet<CertificateContentFlags> contentFlags) throws CertificateException, VectorException {
		switch(subjectType) {
		case rootCa: 
			decodeRootCaScope(byteBuffer, contentFlags); 
			break;
		case secDataExchCa:
		case secDataExchCsr:
		case secDataExchRa:			
			decodeSecDataExchCaScope(byteBuffer, contentFlags);
			break;
		case wsaCa:
		case wsaCsr:
			throw new CertificateException("Unsupported certificate scope: " + subjectType.getValue());
		case crlSigner:
			throw new CertificateException("Unsupported certificate scope: " + subjectType.getValue());
		case secDataExchIdentifiedNotLocalized:
			decodeIdentifiedNotLocalizedScope(byteBuffer, contentFlags);
			break;
		case secDataExchIdentifiedLocalized:
			decodeIdentifiedScope(byteBuffer, contentFlags);
			break;
		case secDataExchAnonymous:
			decodeAnonymousScope(byteBuffer, contentFlags);
			break;
		case wsa:
		default:
			throw new CertificateException("Unsupported certificate scope: " + subjectType.getValue());
		}
	}
	
	/**
	 * Decodes RootCaScope
	 * @param byteBuffer buffer to decode from
	 * @param contentFlags content flags
	 * @throws VectorException if decoding fails
	 * @throws CertificateException if decoding fails
	 */
	private void decodeRootCaScope(ByteBuffer byteBuffer, EnumSet<CertificateContentFlags> contentFlags) throws VectorException, CertificateException {
		// uint8 name<var>;
		byte[] name = OpaqueVariableLengthVector.decode(byteBuffer);
		log.debug("RootCaScope name: " + new String(name));
		// SubjectTypeFlags permitted_subject_types; flags are encoded as PSIDs
		int subjectTypeFlagsValue = PSIDHelper.decodePSID(byteBuffer);

		EnumSet<SubjectTypeFlags> subjectTypeFlags = SubjectTypeFlags.create(subjectTypeFlagsValue);

		if ( subjectTypeFlags == null )
			throw new CertificateException("Unexpected subject type flags value in root ca scope: " + subjectTypeFlagsValue);
		boolean permissionsSet = false;
		if ( SubjectTypeFlags.anyOf(subjectTypeFlags, 
				SubjectTypeFlags.secDataExchCa, 
				SubjectTypeFlags.secDataExchCsr, 
				SubjectTypeFlags.secDataExchIdentifiedNotLocalized,
				SubjectTypeFlags.secDataExchIdentifiedLocalized,
				SubjectTypeFlags.secDataExchAnonymous) ) {
			// PsidArray secure_data_permissions;
			PsidArray psidArray = PsidArray.decode(byteBuffer);
			permissionsSet = true;
			log.debug("RootCaScope PsidArray: " + psidArray);
		}  
		if ( SubjectTypeFlags.anyOf(subjectTypeFlags, SubjectTypeFlags.wsaCa, SubjectTypeFlags.wsaCsr, SubjectTypeFlags.wsa) ) {
			// PsidPriorityArray wsa_permissions; 
			PsidPriorityArray psidPriorityArray = PsidPriorityArray.decode(byteBuffer);
			permissionsSet = true;
			log.debug("RootCaScope PsidPriorityArray: " + psidPriorityArray);
		} 
		if ( !permissionsSet ) {
			// opaque other_permissions<var>;
			byte[] otherPermissions = OpaqueVariableLengthVector.decode(byteBuffer);
			log.debug("Root CA Scope. otherPermissions: " + Hex.encodeHexString(otherPermissions));
		}
		// GeographicRegion region;
		decodeGeographicRegion(byteBuffer);
	}
	
	/**
	 * Decodes SecDataExchCaScope
	 * @param byteBuffer buffer to decode from
	 * @param contentFlags content flags
	 * @throws VectorException if decoding fails
	 * @throws CertificateException if decoding fails
	 */
	private void decodeSecDataExchCaScope(ByteBuffer byteBuffer, EnumSet<CertificateContentFlags> contentFlags) throws VectorException, CertificateException  {
		// uint8 name<var>;
		byte[] name = OpaqueVariableLengthVector.decode(byteBuffer);
		log.debug("SecDataExchCaScope Scope. name: " + new String(name));		
		// SubjectTypeFlags permitted_subject_types; flags are encoded as PSIDs
		int subjectTypeFlagsValue = PSIDHelper.decodePSID(byteBuffer);
		log.debug("SecDataExchCaScope Scope. permitted_subject_types: " + subjectTypeFlagsValue);
		// PsidArray permissions;
		PsidArray psidArray = PsidArray.decode(byteBuffer);
		log.debug("SecDataExchCaScope Scope. PsidArray: " + psidArray);
		// GeographicRegion region;
		decodeGeographicRegion(byteBuffer);
	}
	
	/**
	 * Decodes IdentifiedNotLocalizedScope
	 * @param byteBuffer buffer to decode from
	 * @param contentFlags content flags
	 * @throws VectorException 
	 */
	private void decodeIdentifiedNotLocalizedScope(ByteBuffer byteBuffer, EnumSet<CertificateContentFlags> contentFlags) throws VectorException {
		// uint8 name<var>;
		byte[] name = OpaqueVariableLengthVector.decode(byteBuffer);
		log.debug("IdentifiedNotLocalizedScope Scope. name: " + new String(name));	
		// PsidSspArray permissions;
		PsidSspArray permissions = PsidSspArray.decode(byteBuffer);
		log.debug("IdentifiedNotLocalizedScope Scope. PsidSspArray: " + permissions);
	}
	
	/**
	 * Decodes IdentifiedScope
	 * @param byteBuffer buffer to decode from
	 * @param contentFlags content flags
	 * @throws VectorException if decoding fails
	 * @throws CertificateException if decoding fails
	 */
	private void decodeIdentifiedScope(ByteBuffer byteBuffer, EnumSet<CertificateContentFlags> contentFlags) throws VectorException, CertificateException {
		// uint8 name<var>;
		byte[] name = OpaqueVariableLengthVector.decode(byteBuffer);
		log.debug("IdentifiedScope Scope. name: " + new String(name));	
		// PsidSspArray permissions;
		PsidSspArray permissions = PsidSspArray.decode(byteBuffer);
		log.debug("IdentifiedScope Scope. PsidSspArray: " + permissions);
		// GeographicRegion region;
		decodeGeographicRegion(byteBuffer);
	}
	
	/**
	 * Decodes AnonymousScope
	 * @param byteBuffer buffer to decode from
	 * @param contentFlags content flags
	 * @throws VectorException if decoding fails
	 * @throws CertificateException if decoding fails
	 */
	private void decodeAnonymousScope(ByteBuffer byteBuffer, EnumSet<CertificateContentFlags> contentFlags) throws VectorException, CertificateException {
		// opaque additional_data<var>;
		byte[] additionalData = OpaqueVariableLengthVector.decode(byteBuffer);
		log.debug("AnonymousScope Scope. additional_data: " + Hex.encodeHexString(additionalData));	
		// PsidSspArray permissions;
		PsidSspArray permissions = PsidSspArray.decode(byteBuffer);
		log.debug("AnonymousScope Scope. PsidSspArray: " + permissions);
		// GeographicRegion region;
		decodeGeographicRegion(byteBuffer);
	}
	
	/**
	 * Decodes GeographicRegion
	 * @param byteBuffer buffer to decode from
	 * @throws CertificateException if decoding fails
	 * @throws VectorException if decoding fails
	 */
	private void decodeGeographicRegion(ByteBuffer byteBuffer) throws CertificateException, VectorException {
		GeographicRegion geographicRegion = GeographicRegion.decode(byteBuffer);
		log.debug(String.format("GeographicRegion type: %s (%d)",geographicRegion.regionType, geographicRegion.regionType.getValue()));
	}
	
	/**
	 * Finds signer certificate by digest
	 * @param signerCertId8 singer digest
	 * @return signer certificate
	 */
	private Certificate getSignerCertificate (byte[] signerCertId8) {
		Certificate signerCertificate = null;
		if ( signerCertId8 != null ) {
			signerCertificate = CertificateManager.get(signerCertId8);
			if ( rootPublicCertificate != null &&  !Arrays.equals(rootPublicCertificate.getCertID8(), signerCertId8))
				log.warn("Signer certificate with CertId8 " + Hex.encodeHexString(signerCertId8) + " not found in the certificate store. Falling back for root CA");
		}
		if ( signerCertificate == null )
			signerCertificate = getRootPublicCertificate();
		return signerCertificate;
	}
	
	/**
	 * Retrieves certificate signing certificate instance
	 * @return certificate signing certificate
	 */
	static private Certificate getRootPublicCertificate() {
		if ( rootPublicCertificate == null ) {
			synchronized(Certificate.class) {
				if ( rootPublicCertificate == null )
					rootPublicCertificate = CertificateManager.get(rootPublicCertificateFriendlyName);
			}
		}
		return rootPublicCertificate;
	}
	
	/**
	 * Retrieves a friendly name of the certificate signing certificate 
	 * @return certificate's friendly name
	 */
	public static String getRootPublicCertificateFriendlyName() {
		return rootPublicCertificateFriendlyName;
	}

	/**
	 * Assigns a new friendly name of the certificate signing certificate
	 * @param rootPublicCertificateFriendlyName new friendly name 
	 */
	public static void setRootPublicCertificateFriendlyName(
			String rootPublicCertificateFriendlyName) {
		Certificate.rootPublicCertificateFriendlyName = rootPublicCertificateFriendlyName;
	}
	
	/**
	 * Decrypts encrypted certificate
	 * @param cryptoProvider cryptographic provider to use
	 * @param byteBuffer buffer to decrypt from
	 * @param decryptionKey decryption key to use
	 * @return full certificate
	 * @throws DecoderException
	 * @throws CryptoException
	 * @throws CertificateException
	 */
    private static Certificate decrypt(CryptoProvider cryptoProvider, ByteBuffer byteBuffer, byte[] decryptionKey) throws DecoderException, CryptoException, CertificateException {

    	byte version = byteBuffer.get(); 			// read version
    	assert(version == 2);
    	
    	int certificateCount = byteBuffer.getInt();	// appears to be certificate count
       	assert(certificateCount == 1);
       	
    	int validityPeriod = byteBuffer.getInt(); 	// validity period in seconds
    	log.debug("validityPeriod: " + validityPeriod + " '" + Integer.toBinaryString(validityPeriod) + "'");
    	
    	byte[] nonce = new byte[AESProvider.nonceLength];
    	byteBuffer.get(nonce);
    	log.debug("nonce: " + Hex.encodeHexString(nonce));
    	
    	int length = byteBuffer.get() & 0xFF;
    	log.debug("length: " + length);
    	
    	byte[] cipherText = new byte[length];
    	byteBuffer.get(cipherText);
    	log.debug("cipher: " + Hex.encodeHexString(cipherText));
    	
    	CryptoHelper cryptoHelper = new CryptoHelper(cryptoProvider);
    	KeyParameter key = new KeyParameter(decryptionKey); 

    	byte[] clearText = cryptoHelper.decryptSymmetric(key, nonce, cipherText);
    	
		byte[] privateSigningKeyBytes = new byte[ECDSAProvider.ECDSAPrivateKeyEncodedLength];
		byte[] privateEncryptionKeyBytes = new byte[ECDSAProvider.ECDSAPrivateKeyEncodedLength];
		byte[] certificateBytes = new byte[clearText.length - 2*ECDSAProvider.ECDSAPrivateKeyEncodedLength];
		
		System.arraycopy(clearText,  0, privateSigningKeyBytes, 0, ECDSAProvider.ECDSAPrivateKeyEncodedLength);
		System.arraycopy(clearText,  ECDSAProvider.ECDSAPrivateKeyEncodedLength, privateEncryptionKeyBytes, 0, ECDSAProvider.ECDSAPrivateKeyEncodedLength);
		System.arraycopy(clearText,  2*ECDSAProvider.ECDSAPrivateKeyEncodedLength, certificateBytes, 0, certificateBytes.length);
		
    	log.debug("privateSigningKey:    " + Hex.encodeHexString(privateSigningKeyBytes));
    	log.debug("privateEncryptionKey: " + Hex.encodeHexString(privateEncryptionKeyBytes));
    	log.debug("certificate: 		 " + Hex.encodeHexString(certificateBytes));
    	
    	Certificate certificate = Certificate.fromBytes(new CryptoProvider(), certificateBytes);
    	if ( certificate != null ) {
    		ECDSAProvider ecdsaProvider = cryptoProvider.getSigner();
    		ECPrivateKeyParameters  privateSigningKey = ecdsaProvider.decodePrivateKey(privateSigningKeyBytes);
       		ECPrivateKeyParameters  privateEncryptionKey = ecdsaProvider.decodePrivateKey(privateEncryptionKeyBytes);
       		certificate.setSigningPrivateKey(privateSigningKey);
       		certificate.setEncryptionPrivateKey(privateEncryptionKey);
    	}
    	
    	return certificate;
    }

}
