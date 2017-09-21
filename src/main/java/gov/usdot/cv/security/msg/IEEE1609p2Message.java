package gov.usdot.cv.security.msg;

import java.nio.ByteBuffer;
import java.util.Date;
import java.util.EnumSet;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import gov.usdot.cv.security.clock.ClockHelper;
import gov.usdot.cv.security.cert.Certificate;
import gov.usdot.cv.security.cert.CertificateException;
import gov.usdot.cv.security.cert.CertificateManager;
import gov.usdot.cv.security.cert.region.ThreeDLocation;
import gov.usdot.cv.security.crypto.AESProvider;
import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoHelper;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.crypto.ECDSASignature;
import gov.usdot.cv.security.type.MsgContentType;
import gov.usdot.cv.security.type.MsgSignerIDType;
import gov.usdot.cv.security.type.TbsDataFlags;
import gov.usdot.cv.security.util.ByteBufferHelper;
import gov.usdot.cv.security.util.PSIDHelper;
import gov.usdot.cv.security.util.Time64Helper;
import gov.usdot.cv.security.util.vector.OpaqueVariableLengthVector;
import gov.usdot.cv.security.util.vector.VectorException;

/**
 * Instance of an IEEE 1609.2 Message
 *
 */
public class IEEE1609p2Message {
	
	private static final Logger log = Logger.getLogger(IEEE1609p2Message.class);
	
	private static String selfCertificateFriendlyName  = "Self";

	private static final int defaultByteBufferSize = 1<<17-1; // 65535 - max UDP packet that we support
	
	/**
	 * CryptoProvider to be used for all cryptographic operations by this instance
	 */
	protected final CryptoProvider cryptoProvider;
	
	/**
	 * CryptoHelper to be used for all cryptographic operations by this instance
	 */
	protected final CryptoHelper cryptoHelper;
	
	static private final byte protocolVersion = 2;
	static private final byte symmAlgorithmAes128ccm = 0;
	
	private Certificate selfCertificate = CertificateManager.get(IEEE1609p2Message.selfCertificateFriendlyName);
	
	private MsgContentType contentType;
	private MsgSignerIDType signerIDType;
	private Certificate certificate;
	private byte[] certID8;
	private Integer psid;
	private byte[] payload;
	private Long generationTime;
	private Long expiryTime;

	/**
	 * Private constructor which will create cryptographic provider
	 */
	public IEEE1609p2Message() {
		this(null);
	}
	
	/**
	 * Private constructor with explicit cryptographic provider
	 * @param cryptoProvider the provider
	 */
	public IEEE1609p2Message(CryptoProvider cryptoProvider) {
		if ( cryptoProvider == null  )
			cryptoProvider = new CryptoProvider();
		this.cryptoProvider = cryptoProvider;
		this.cryptoHelper = new CryptoHelper(cryptoProvider);
	}
	
	/**
	 * Creates IEEE 1609.2 Message from bytes
	 * @param msgBytes message bytes (typically received over UDP)
	 * @return IEEE1609p2Message instance
	 * @throws MessageException if bytes do not represent an IEEE 1609.2 Message
	 * @throws CertificateException if certificate in the message is not valid
	 * @throws VectorException if decoding fails
	 * @throws CryptoException if symmetric decryption fails
	 */
	static public IEEE1609p2Message parse(byte[] msgBytes ) throws MessageException, CertificateException, VectorException, CryptoException {
		return parse(msgBytes, new CryptoProvider());
	}
	
	/**
	 * Creates IEEE 1609.2 Message from bytes with explicit cryptographic provider
	 * @param msgBytes message bytes (typically received over UDP)
	 * @param cryptoProvider thread wide cryptographic provider instance
	 * @return IEEE1609p2Message instance
	 * @throws MessageException if bytes do not represent an IEEE 1609.2 Message
	 * @throws CertificateException if certificate in the message is not valid
	 * @throws VectorException if decoding fails
	 * @throws CryptoException if symmetric decryption fails
	 */
	static public IEEE1609p2Message parse(byte[] msgBytes, CryptoProvider cryptoProvider) throws MessageException, CertificateException, VectorException, CryptoException {
		return 	parse(ByteBuffer.wrap(msgBytes), cryptoProvider);
	}
	
	/**
	 * Creates IEEE 1609.2 Message from bytes with explicit cryptographic provider
	 * @param byteBuffer message byte buffer
	 * @param cryptoProvider thread wide cryptographic provider instance
	 * @return IEEE1609p2Message instance
	 * @throws MessageException if bytes do not represent an IEEE 1609.2 Message
	 * @throws CertificateException if certificate in the message is not valid
	 * @throws VectorException if decoding fails
	 * @throws CryptoException if symmetric decryption fails
	 */
	static public IEEE1609p2Message parse(ByteBuffer byteBuffer, CryptoProvider cryptoProvider) throws MessageException, CertificateException, VectorException, CryptoException {
		if ( byteBuffer == null )
			return null;
		if ( byteBuffer.remaining() < 80 )
			throw new MessageException(String.format("Parameter byteBuffer is too short. Buffer bytes: %d.", byteBuffer.remaining() ));
		// Version -- peek only
		int version = byteBuffer.array()[0] & 0xFF;
		if ( version != protocolVersion )
			throw new MessageException(String.format("Unexpected Protocol Version value. Expected %d, Actual: %d.", version, protocolVersion));
		
		// Content Type -- peek only
		int intContentType = byteBuffer.array()[1] & 0xFF;
		MsgContentType contentType = MsgContentType.valueOf(intContentType);
		if ( contentType == MsgContentType.Signed )
			return parseSigned(byteBuffer, cryptoProvider, true);
		
		if ( contentType == MsgContentType.Encrypted )
			return parseEncrypted(byteBuffer, cryptoProvider);
		
		throw new MessageException(String.format("Unexpected Content Type value %d.", intContentType));
	}
	
	/**
	 * Creates IEEE 1609.2 Message from signed bytes with explicit cryptographic provider
	 * @param byteBuffer message byte buffer
	 * @param cryptoProvider thread wide cryptographic provider instance
	 * @param hasProtocolVersion true if protocolVersion is present and false otherwise
	 * @return IEEE1609p2Message instance
	 * @throws MessageException if bytes do not represent an IEEE 1609.2 Message
	 * @throws CertificateException if certificate in the message is not valid
	 * @throws VectorException if decoding fails
	 */
	static private IEEE1609p2Message parseSigned(ByteBuffer byteBuffer, CryptoProvider cryptoProvider, boolean hasProtocolVersion) throws MessageException, CertificateException, VectorException {
		IEEE1609p2Message msg = new IEEE1609p2Message(cryptoProvider);
		if ( hasProtocolVersion )
			byteBuffer.get();	// skip protocolVersion
		byteBuffer.get();		// skip contentType
		msg.contentType = MsgContentType.Signed;

		// Signer ID Type -- Digest or Certificate
		int msgSignerIDType = byteBuffer.get() & 0xFF;
		msg.signerIDType = MsgSignerIDType.valueOf(msgSignerIDType);
		if ( msg.signerIDType == MsgSignerIDType.DigestEcdsap256) {
			msg.certID8 = new byte[8];
			byteBuffer.get(msg.certID8);
		} else if (msg.signerIDType == MsgSignerIDType.Certificate) {
			msg.certificate = Certificate.fromBytes(msg.cryptoProvider, byteBuffer);
		} else {
			throw new MessageException(String.format("Unexpected Signer ID Type value %d.", msgSignerIDType));
		}
		
		// validate client certificate
		msg.validateCertificate();
		assert(msg.certificate != null);
		
		int startOfToBeSignedData = byteBuffer.position();
				
		// TbsDataFlags (flags are encoded as PSIDs)
		int tbsDataFlagsValue = PSIDHelper.decodePSID(byteBuffer);
		EnumSet<TbsDataFlags> tbsDataFlags = TbsDataFlags.create(tbsDataFlagsValue);
		if ( tbsDataFlags == null )
			throw new MessageException(String.format("Unexpected Msg Flag value %d.", tbsDataFlagsValue));

		// PSID
		msg.psid = PSIDHelper.decodePSID(byteBuffer);
		log.debug(String.format("psid: 0x%x", msg.psid));
		if ( msg.psid == -1 )
			throw new MessageException(String.format("Couldn't decode PSID value. See log file for details."));
		
		// Payload data
		msg.payload = OpaqueVariableLengthVector.decode(byteBuffer);
		log.debug("payload: " + Hex.encodeHexString(msg.payload));
		
		// Extras
		boolean otherFlag = true;
		if ( TbsDataFlags.anyOf(tbsDataFlags, TbsDataFlags.useGenerationTime ) ) {
			// Time64WithConfidence generation_time; 	// Generation Time 6.2.10 Time64WithConfidence
			msg.generationTime = byteBuffer.getLong();	// Time64  time; // 6.2.11 Time64
			int confidence = byteBuffer.get() & 0xFF;
			log.debug(String.format("TbsDataFlags.useGenerationTime: Time64WithConfidence: time: %s, confidence %d.", Time64Helper.time64ToDate(msg.generationTime), confidence));
			otherFlag = false;
		}
		if ( TbsDataFlags.anyOf(tbsDataFlags, TbsDataFlags.expires ) ) {
			// Time64 expiry_time; // 6.2.11 Time64
			msg.expiryTime = byteBuffer.getLong();
			log.debug("TbsDataFlags.expires: " + Time64Helper.time64ToDate(msg.expiryTime));
			otherFlag = false;
		}
		if ( TbsDataFlags.anyOf(tbsDataFlags, TbsDataFlags.useLocation ) ) {
			// ThreeDLocation generation_location;
			ThreeDLocation threeDLocation = ThreeDLocation.decode(byteBuffer);
			log.debug("UseLocation: " + threeDLocation);
			otherFlag = false;
		}
		if ( TbsDataFlags.anyOf(tbsDataFlags, TbsDataFlags.extensions ) ) {
			// TbsDataExtension extensions<var>;
			// 		TbsDataExtensionType  type;
            // 		opaque                value<var>;
			int type = byteBuffer.get() & 0xFF;
			byte[] value = OpaqueVariableLengthVector.decode(byteBuffer);
			log.debug(String.format("TbsDataFlags.extensions type = 0x%x. Other data: ", type, Hex.encodeHexString(value)));
			otherFlag = false;
		}
		if ( otherFlag ) {
			// opaque other_data<var>;
			byte[] other_data = OpaqueVariableLengthVector.decode(byteBuffer);
			log.debug(String.format("TbsDataFlags = %d. Other data: ", tbsDataFlagsValue, Hex.encodeHexString(other_data)));
		}
		
		// End of unsigned data
		int endOfToBeSignedData = byteBuffer.position();

		// Decode and validate signature
		ECDSASignature signature = ECDSASignature.decode(byteBuffer, cryptoProvider.getSigner());
		ECPublicKeyParameters signingPublicKey = msg.certificate.getSigningPublicKey();
		if ( !msg.cryptoHelper.verifySignature(byteBuffer.array(), startOfToBeSignedData, endOfToBeSignedData - startOfToBeSignedData, signingPublicKey, signature) ) {
			log.error("Message signature is not valid");
			throw new MessageException("Message signature is not valid");
		}

		return msg;
	}
	
	/**
	 * Parse encrypted message
	 * @param byteBuffer buffer to parse
	 * @param cryptoProvider cryptographic provider to use
	 * @return IEEE1609p2Message instance
	 * @return IEEE1609p2Message instance
	 * @throws MessageException if bytes do not represent an IEEE 1609.2 Message
	 * @throws CertificateException if certificate in the message is not valid
	 * @throws VectorException if decoding fails
	 * @throws CryptoException if decryption fails
	 */
	static private IEEE1609p2Message parseEncrypted(ByteBuffer byteBuffer, CryptoProvider cryptoProvider) throws MessageException, CertificateException, VectorException, CryptoException {
		IEEE1609p2Message msg = new IEEE1609p2Message(cryptoProvider);
		byteBuffer.get();	// skip protocolVersion
		byteBuffer.get();	// skip contentType
		
		// SymmAlgorithm symm_algorithm;
		byte symmAlgorithm = byteBuffer.get();
		if ( symmAlgorithm != symmAlgorithmAes128ccm )
			throw new MessageException(String.format("Unexpected Msg Flag value. Expected %d, Actual: %d.", symmAlgorithmAes128ccm, symmAlgorithm));
	
		// RecipientInfo recipients<var>;
		KeyParameter symmetricKey = null;
		RecipientInfoVector recipientInfoVector = new RecipientInfoVector();
		recipientInfoVector.decode(byteBuffer, new RecipientInfo(cryptoProvider, msg.getSelfCertificate().getCertID8()));
		for( RecipientInfo recipientInfo : recipientInfoVector) {
			symmetricKey = recipientInfo.getAesEncryptionKey();
			if ( symmetricKey != null )
				break;
		}
		if ( symmetricKey == null )
			throw new MessageException("Coulnd't retrieve symmetric encryption key from the recipient information vector");
		
		byte[] nonce = new byte[AESProvider.nonceLength];
		byteBuffer.get(nonce);
		byte[] ccmCipherText = OpaqueVariableLengthVector.decode(byteBuffer);
		
		CryptoHelper helper = new CryptoHelper(cryptoProvider);
		byte[] clearText = helper.decryptSymmetric(symmetricKey, nonce, ccmCipherText);
		
		// clearText is just a signed message without the protocol version
		msg = parseSigned(ByteBuffer.wrap(clearText), cryptoProvider, false);
		msg.contentType = MsgContentType.Encrypted;
		return msg;
	}
	
	/**
	 * Encode signed 1609.2 message with self public certificate as signer identifier
	 * @param payloadBytes payload message data
	 * @return encoded message bytes
	 * @throws VectorException if encoding fails
	 * @throws CertificateException if self certificate was not found
	 */
	public byte[] sign(byte[] payloadBytes) throws VectorException, CertificateException {
		return sign(payloadBytes, true, true);
	}
	
	/**
	 * Encode signed 1609.2 message
	 * @param payloadBytes payload message data
	 * @param withCertificate if true use self public certificate as signer identifier, otherwise use CertID8 digest
	 * @return encoded message bytes
	 * @throws VectorException if encoding fails
	 * @throws CertificateException if self certificate was not found
	 */
	public byte[] sign(byte[] payloadBytes, boolean withCertificate) throws VectorException, CertificateException {
		return sign(payloadBytes, withCertificate, true);
	}
	
	/**
	 * Encode signed 1609.2 message
	 * @param payloadBytes payload message data
	 * @param withCertificate if true use self public certificate as signer identifier, otherwise use CertID8 digest	 
	 * @param includeProtocolVersion if true protocolVesion will be present, otherwise it will be skipped as needed for creation ToBeEncrypted element.
	 * @return encoded message bytes
	 * @throws VectorException if encoding fails
	 * @throws CertificateException if self certificate was not found
	 */
	private byte[] sign(byte[] payloadBytes, boolean withCertificate, boolean includeProtocolVersion) throws VectorException, CertificateException {
		ByteBuffer byteBuffer = ByteBuffer.allocate(defaultByteBufferSize);
		if ( includeProtocolVersion )
			byteBuffer.put(protocolVersion);
		contentType = MsgContentType.Signed;
		byteBuffer.put((byte)contentType.getValue());
		certificate = getSelfCertificate();
		if ( withCertificate ) {
			byteBuffer.put((byte)MsgSignerIDType.Certificate.getValue());
			byteBuffer.put(certificate.getBytes());
		} else {
			byteBuffer.put((byte)MsgSignerIDType.DigestEcdsap256.getValue());
			byteBuffer.put(certificate.getCertID8());
		}
		int startToBeSignedData = byteBuffer.position();
		PSIDHelper.encodePSID(byteBuffer, TbsDataFlags.useGenerationTime.getValue());
		PSIDHelper.encodePSID(byteBuffer, psid);
		payload = payloadBytes;
		OpaqueVariableLengthVector.encode(byteBuffer, payload);
		// Generation Time 6.2.10 Time64WithConfidence
		generationTime = Time64Helper.dateToTime64(ClockHelper.nowDate()); 
		byteBuffer.putLong(generationTime); // Time64  time;
		byteBuffer.put((byte)0);			// confidence 0
		int endToBeSignedData = byteBuffer.position();
		ECPrivateKeyParameters signingPrivateKey = getSelfCertificate().getSigningPrivateKey();
		ECDSASignature signature = cryptoHelper.computeSignature(byteBuffer.array(), startToBeSignedData, endToBeSignedData - startToBeSignedData, signingPrivateKey);
		signature.encode(byteBuffer);
		return ByteBufferHelper.copyBytes(byteBuffer);
	}

	/**
	 * Encode encrypted 1609.2 message with signer id digest
	 * @param payload payload message data
	 * @param recipients variable argument list of CredID8 for recipients
	 * @return encoded 1609.2 message
	 * @throws CertificateException  if recipient certificate can not be found
	 * @throws VectorException if vector of recipient was not encoded properly
	 * @throws CryptoException if symmetric encryption fails
	 */
	public byte[] encrypt(byte[] payload, byte[] ... recipients) throws CertificateException, VectorException, CryptoException {
		return encrypt(payload, false, recipients);
	}
	
	/**
	 * Encode encrypted 1609.2 message
	 * @param payload payload message data
	 * @param withCertificate if true signer id will be certificate, otherwise digest
	 * @param recipients variable argument list of CredID8 for recipients
	 * @return encoded 1609.2 message
	 * @throws CertificateException if recipient certificate can not be found
	 * @throws VectorException if vector of recipient was not encoded properly
	 * @throws CryptoException if symmetric encryption fails
	 */
	public byte[] encrypt(byte[] payload, boolean withCertificate, byte[] ... recipients) throws CertificateException, VectorException, CryptoException {
		ByteBuffer byteBuffer = ByteBuffer.allocate(defaultByteBufferSize);
		byteBuffer.put(protocolVersion);
		contentType = MsgContentType.Encrypted;
		byteBuffer.put((byte)contentType.getValue());
		
		this.payload = payload;
		contentType = MsgContentType.Encrypted;
		
		// SymmAlgorithm symm_algorithm; 
		byteBuffer.put(symmAlgorithmAes128ccm);
		KeyParameter symmetricKey = AESProvider.generateKey();
		
		// RecipientInfo recipients<var>;
		RecipientInfoVector recipientInfoVector = new RecipientInfoVector();
		for( byte[] recipient : recipients)
			recipientInfoVector.add(new RecipientInfo(cryptoProvider, recipient, symmetricKey));
		recipientInfoVector.encode(byteBuffer);
		
		// clear bytes to be encrypted are a signed message but without the protocol version
		byte[] clearText = sign(payload, withCertificate, false);
		
		// AesCcmCiphertext
		CryptoHelper helper = new CryptoHelper(cryptoProvider);
		byte[] nonce = CryptoHelper.getSecureRandomBytes(AESProvider.nonceLength);
		byte[] ccmCipherText = helper.encryptSymmetric(symmetricKey, nonce, clearText);
		byteBuffer.put(nonce);
		OpaqueVariableLengthVector.encode(byteBuffer, ccmCipherText);
		
		return ByteBufferHelper.copyBytes(byteBuffer);
	}

	/**
	 * Retrieves Provider Service Identifier for this message
	 * @return Provider Service Identifier value
	 */
	public Integer getPSID() {
		return psid;
	}

	/**
	 * Assigns Provider Service Identifier for this message
	 * @param psid new Assigns Provider Service Identifier value
	 */
	public void setPSID(Integer psid) {
		this.psid = psid;
	}
	
	/**
	 * Retrieves signer ID type
	 * @return signer ID type
	 */
	public MsgSignerIDType getSignerIDType() {
		return signerIDType;
	}

	/**
	 * Retrieves payload bytes from the message
	 * @return payload bytes as clear text
	 */
	public byte[] getPayload() {
		return payload;
	}

	/**
	 * Retrieves sender's public certificate
	 * @return sender's public certificate or null in one is not present in the message
	 */
	public Certificate getCertificate() {
		return certificate;
	}
	
	/**
	 * Retrieves sender's certificate digest
	 * @return sender's certificate digest or null in one is not present in the message
	 */
	public byte[] getCertID8() {
		return certID8;
	}
	
	/**
	 * Retrieves message generation time
	 * @return message generation time as Date
	 */
	public Date getGenerationTime() {
		return Time64Helper.time64ToDate(generationTime);
	}
	
	/**
	 * Validates a certificate
	 * @throws MessageException if a certificate can not be resolved via certificate or certID8
	 * @throws CertificateException if certificate  is not valid
	 */
	private void validateCertificate() throws CertificateException, MessageException {
		if ( certificate == null && certID8 == null )
			throw new MessageException("No certificate and no digest found in the message.");
		if ( certificate == null ) {
			certificate = CertificateManager.get(certID8);
			if ( certificate == null )
				throw new MessageException(String.format("Certificate for provided CertID8 %s was not found", Hex.encodeHexString(certID8)));
		} else {
			certID8 = certificate.getCertID8();
		}
		assert(certificate != null);
		assert(certID8 != null);
		if ( certificate.isValid()) {
			CertificateManager.put(certID8, certificate);
		} else {
			if ( CertificateManager.get(certID8) != null )
				CertificateManager.remove(certID8);
			throw new CertificateException(String.format("Certificate for CertID8 %s is not valid", Hex.encodeHexString(certID8)));
		}
	}
	
	/**
	 * Assigns global certificate store friendly certificate name for this entity.
	 * Note that all existing instances will continue using the selfCertificate that was in place when they were created
	 * @param friendlyName friendly certificate name to assign
	 */
	static public void setSelfCertificateFriendlyName(String friendlyName) {
		selfCertificateFriendlyName  = friendlyName;
		log.debug(String.format("New self certificate friendly name: '%s'", selfCertificateFriendlyName));
	}
	
	/**
	 * Retrieves self certificate.
	 * The certificate is always a public certificate with private keys set after it has been instantiated. 
	 * In other words, it has private keys but getBytes() returns a public certificate that only has public keys
	 * and thus is suitable for adding to a message as signer ID.
	 * @return self certificate
	 * @throws CertificateException 
	 */
	private Certificate getSelfCertificate() throws CertificateException {
		if (selfCertificate == null) {
			synchronized(this) {
				if (selfCertificate == null) {
					selfCertificate = CertificateManager.get(IEEE1609p2Message.selfCertificateFriendlyName);
					if ( selfCertificate == null )
						throw new CertificateException(String.format("Self certificate with name '%s' was not found", IEEE1609p2Message.selfCertificateFriendlyName));
				}
			}
		}
		assert(selfCertificate != null);
		return selfCertificate;
	}

}
