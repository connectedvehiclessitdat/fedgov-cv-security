package gov.usdot.cv.security.msg;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.Arrays;
import java.util.Date;

import gov.usdot.cv.security.cert.Certificate;
import gov.usdot.cv.security.cert.CertificateException;
import gov.usdot.cv.security.cert.CertificateManager;
import gov.usdot.cv.security.cert.MockCertificateStore;
import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.type.MsgSignerIDType;
import gov.usdot.cv.security.util.UnitTestHelper;
import gov.usdot.cv.security.util.vector.VectorException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class IEEE1609p2MessageTest {

	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(IEEE1609p2MessageTest.class);
	
	private static final int TestPsid = 0x2fe1;
	
	// sample CV J2735 messages
	static final String serviceRequestHex  = "301C8002009B810101820420013E16A30DA00680046C0F173A810300C351";
	static final String serviceResponseHex = "30638002009B810101820420013E16A314800207DE81010982011383010A84012D85027530A41CA00C800419A147808104CD560780A10C800418701A808104CF1FCB0085200000000000000000000000000000000000000000000000000000000000000000";
	static final String vehSitDataHex      = "308203728002009A810105820420013E16830104A476A025A013800207DD81010C82010983010984011E85011E8104CE4574248204194D066F83020348820109A34A8348FFEEFEB400000064FFF9FEC800000064FFF8FE9A000000640000FEB200000064FFFBFEA8FF9C0064FFFEFEB200000064FFFBFE9C00000064FFF5FEBE00000064FFEDFEA800000064A58202E23050800420013E16A113800207DD81010C82010983010984011E85011EA2108004194D066F8104CE45742482020348A3218002E6728101688201318307000100012B000084020965A50880020104810200EC3050800420013E16A113800207DD81010C82010983010984011E85011EA2108004194D05438104CE45740E8202034AA3218002E6728101688201318307000100012B000084020965A50880020104810200EC3050800420013E16A113800207DD81010C82010983010984011E85011EA2108004194D042B8104CE45740E8202034AA3218002E6728101688201318307000100012B000084020965A50880020104810200EC3050800420013E16A113800207DD81010C82010983010984011E85011EA2108004194D02E88104CE4573FC8202034AA3218002E6728101688201318307000100012B000084020965A50880020104810200EC3050800420013E16A113800207DD81010C82010983010984011E85011EA2108004194D01BB8104CE4573FB8202034AA3218002E6728101688201318307000100012B000084020965A50880020104810200EC3050800420013E16A113800207DD81010C82010983010984011E85011EA2108004194D00858104CE4573F482020349A3218002E6728101688201318307000100012B000084020965A50880020104810200EC3050800420013E16A113800207DD81010C82010983010984011E85011DA2108004194CFF588104CE4573F382020349A3218002E6728101688201318307000100012B000084020965A50880020104810200EC3050800420013E16A113800207DD81010C82010983010984011E85011DA2108004194CFE178104CE4573EC82020349A3218002E6728101688201318307000100012B000084020965A50880020104810200EC3050800420013E16A113800207DD81010C82010983010984011E85011DA2108004194CFCF48104CE4573DF82020349A3218002E6728101688201318307000100012B000084020965A50880020104810200EC86023132";

	static byte[] serviceRequest, serviceResponse, vehSitData;
	
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
		CryptoProvider.initialize();
		
		serviceRequest  = Hex.decodeHex(serviceRequestHex.toCharArray());
		serviceResponse = Hex.decodeHex(serviceResponseHex.toCharArray());
		vehSitData 		= Hex.decodeHex(vehSitDataHex.toCharArray());
	}

	@Before
	public void setUp() throws Exception {
		CertificateManager.clear();
		TestCertificateStore.load();
	}

	@After
	public void tearDown() throws Exception {
		CertificateManager.clear();
	}

	/**
	 * Use case 1: Client that sends signed-only messages to SDC/SDW
	 * @throws CertificateException if recipient certificate can not be found
	 * @throws VectorException if vector of recipient was not encoded properly
	 * @throws CryptoException if symmetric encryption fails
	 */
	@Test
	public void useCase1() throws VectorException, MessageException, CertificateException, CryptoException {
		// only once on the client side
		IEEE1609p2Message.setSelfCertificateFriendlyName("Client");
		assertNotNull(CertificateManager.get("Client"));
		// prepare
		byte[] sr, vsd1, vsd2, vsd3;
		IEEE1609p2Message msgSend = new IEEE1609p2Message();
		msgSend.setPSID(TestPsid);
		// send signed (with certificate) ServiceRequest in 1609.2 envelope
		send( sr = msgSend.sign(serviceRequest));
		// send signed (with digest) vehSitData messages  in 1609.2 envelope
		send( vsd1 = msgSend.sign(vehSitData, false) );	// signed with digest
		send( vsd2 = msgSend.sign(vehSitData, false) );	// signed with digest
		send( vsd3 = msgSend.sign(vehSitData, true ) );	// signed with certificate (test only)
		// ...........................
		// only once on the receiving side
		IEEE1609p2Message.setSelfCertificateFriendlyName("Self");
		assertNotNull(CertificateManager.get("Self"));
		// receive and verify
		receive( sr, serviceRequest);
		receive( vsd1, vehSitData);
		receive( vsd2, vehSitData);
		receive( vsd3, vehSitData);
	}

	/**
	 * Use case 2: Client that sends encrypted messages to SDC/SDW
	 * @throws CertificateException if recipient certificate can not be found
	 * @throws VectorException if vector of recipient was not encoded properly
	 * @throws CryptoException if symmetric encryption fails
	 */
	@Test
	public void useCase2() throws VectorException, CertificateException, CryptoException {
		// only once on client side
		IEEE1609p2Message.setSelfCertificateFriendlyName("Client");
		byte[] recipient = getSdcRecipient();
		byte[] invalidRecipient = Arrays.copyOf(recipient, recipient.length);
		invalidRecipient[0] += 1;
		
		// prepare
		IEEE1609p2Message msgSend = new IEEE1609p2Message();
		msgSend.setPSID(TestPsid);
		// send signed (with certificate) ServiceRequest in 1609.2 envelope
		send( msgSend.sign(serviceRequest) );
		// send encrypted vehSitData messages  in 1609.2 envelope with digest
		send( msgSend.encrypt(vehSitData, recipient) );
		send( msgSend.encrypt(vehSitData, recipient, recipient) );
		send( msgSend.encrypt(vehSitData, recipient, recipient, recipient) );
		// send encrypted vehSitData messages in 1609.2 envelope with certificate
		send( msgSend.encrypt(vehSitData, true, recipient) );
		send( msgSend.encrypt(vehSitData, true, recipient, recipient) );
		send( msgSend.encrypt(vehSitData, true, recipient, recipient, recipient) );
		// send encrypted vehSitData message to a list of recipients that includes an invalid recipient
		final String msg = "Sending to invalid recipient throws a certificate exception";
		// ... with digest
		try {
			send( msgSend.encrypt(vehSitData, recipient, recipient, invalidRecipient, recipient) );
			assertTrue(msg, false);
		} catch (CertificateException ex ) {
			log.debug(ex);
			assertTrue(msg, true);
		}
		// ... with certificate
		try {
			send( msgSend.encrypt(vehSitData, true, recipient, recipient, invalidRecipient, recipient) );
			assertTrue(msg, false);
		} catch (CertificateException ex ) {
			log.debug(ex);
			assertTrue(msg, true);
		}
		// ...........................
	}
	
	/**
	 * Use case 3: SDC/SDW receives signed or encrypted messages from a client
	 * @throws MessageException if message is invalid
	 * @throws CertificateException if recipient certificate can not be found
	 * @throws VectorException if vector of recipient was not encoded properly
	 * @throws CryptoException if symmetric encryption fails
	 */
	@Test
	public void useCase3() throws MessageException, CertificateException, VectorException, CryptoException {
		final int psid = 0xcafe;
		// only once on client side
		IEEE1609p2Message.setSelfCertificateFriendlyName("Client");
		// verify that this is private certificate
		Certificate clientCert = CertificateManager.get("Client");
		assertNotNull(clientCert.getEncryptionPrivateKey());
		assertNotNull(clientCert.getSigningPrivateKey());
		byte[] recipient = getSdcRecipient();
		// prepare
		CryptoProvider cryptoProvider = new CryptoProvider();
		IEEE1609p2Message msgSend = new IEEE1609p2Message(cryptoProvider);
		msgSend.setPSID(psid);
		// create signed ServiceRequest in 1609.2 envelope
		byte[] signedServiceRequest = msgSend.sign(serviceRequest);
		// create signed VehSitData
		byte[] signedVehSitData = msgSend.sign(vehSitData, false);
		// create encrypted VehSitData
		byte[] encryptedVehSitData = msgSend.encrypt(vehSitData, recipient);
		// pretend that we received the messages
		// pretend that we do not have client's certificate yet, it will be added from the first message
		byte[] clientCertID8 = clientCert.getCertID8();
		CertificateManager.remove("Client");
		assertNull(CertificateManager.get(clientCertID8));
		// only once on SDC/SDW side
		IEEE1609p2Message.setSelfCertificateFriendlyName("Self");
		// decode signed ServiceRequest message
		IEEE1609p2Message msgRecv = IEEE1609p2Message.parse(signedServiceRequest, cryptoProvider);
		byte[] recvServiceRequest = msgRecv.getPayload();
		assertTrue(Arrays.equals(serviceRequest, recvServiceRequest));
		assertEquals(psid, (int)msgRecv.getPSID());
		assertEquals(MsgSignerIDType.Certificate.getValue(), msgRecv.getSignerIDType().getValue());
		// client's certificate was added to the certificate store
		clientCert = CertificateManager.get(clientCertID8);
		assertNotNull(clientCert);
		// verify that it is indeed public certificate that contains no private keys
		assertNull(clientCert.getEncryptionPrivateKey());
		assertNull(clientCert.getSigningPrivateKey());
		// decode and validate signed VehSitData message
		msgRecv = IEEE1609p2Message.parse(signedVehSitData, cryptoProvider);
		assertEquals(MsgSignerIDType.DigestEcdsap256.getValue(), msgRecv.getSignerIDType().getValue());
		byte[] recvVehSitData = msgRecv.getPayload();
		assertTrue(Arrays.equals(vehSitData, recvVehSitData));
		// decode, validate, and decrypt encrypted VehSitData message
		msgRecv = IEEE1609p2Message.parse(encryptedVehSitData, cryptoProvider);
		assertEquals(MsgSignerIDType.DigestEcdsap256.getValue(), msgRecv.getSignerIDType().getValue());
		recvVehSitData = msgRecv.getPayload();
		assertTrue(Arrays.equals(vehSitData, recvVehSitData));
		// check that generation time is not in the future
		long generationTime = msgRecv.getGenerationTime().getTime();
		assertTrue(generationTime < new Date().getTime());
	}
	
	/**
	 * Use case 4: SDC receives signed or encrypted messages destined to multiple recipients (SDC, SWD, & Unknown).
	 * In the recipients list we will add SWD and Unknown recipients.
	 * Client side store will have only public certificates for all three and full certificate for the client.
	 * SDC side store will initially only have full certificate for SDC and public certificate for SDW.
	 * When the first message is received by SDC, client's public certificate will be automatically added.
	 * Having SDW public certificate allows us to test the case when a receipient's certificate exists in the store
	 * but does not contain private encryption key.
	 * Having unknown allows us to test the case when a receipient's public certificate does not exist in the store. 
	 * We also do a test variation when recipient list does not have any valid recipients so the decoding fails.
	 * @throws MessageException if message is invalid
	 * @throws CertificateException if recipient certificate can not be found
	 * @throws VectorException if vector of recipient was not encoded properly
	 * @throws CryptoException if symmetric encryption fails
	 * @throws IOException if certificate load fails
	 * @throws DecoderException if certificate decoding from HEX string fails
	 */
	@Test
	public void useCase4() throws MessageException, CertificateException, VectorException, CryptoException, DecoderException, IOException {
		useCase4(true);		// SDC is added as a recipient so the decryption will be successful
		useCase4(false);	// SDC is not added as a recipient so the decryption will fail
	}
	
	// hasValidRecipient 
	public void useCase4(boolean hasValidRecipient) throws MessageException, CertificateException, VectorException, CryptoException, DecoderException, IOException {
		// Certificate Names
		final String caCertName  = "CA";
		final String clnCertName = "Client";
		final String sdcCertName = "Self";
		final String sdwCertName = "RA";
		final String uknCertName = "Unknown";
		
		CryptoProvider cryptoProvider = new CryptoProvider();
		
		//
		// Client side certificate store setup
		//
		
		// Begin with an empty store
		CertificateManager.clear();
		
		// We must have CA certificate in the store in order to load any other certificates
		TestCertificateStore.load(cryptoProvider, caCertName);
		
		// Add client certificate to the store
		TestCertificateStore.load(cryptoProvider, clnCertName);
		assertNotNull(CertificateManager.get(clnCertName));

		// Add SDC public certificate to the store
		loadPublicCertificate(cryptoProvider, sdcCertName);
		
		// Add SDW public certificate to the store
		TestCertificateStore.load(cryptoProvider, sdwCertName);
		
		// Create Unknown certificates and add only public to the store
		// Note that we simulate Unknown recipient on the receiving side; it is known on the client side
		Certificate[] uknCerts = MockCertificateStore.createCertificates();
		Certificate uknPubCert = uknCerts[1];
		CertificateManager.put(uknCertName, uknPubCert);
		assertNotNull(CertificateManager.get(uknCertName));

		// Create recipients array
		final byte[] sdcRecipient = CertificateManager.get(sdcCertName).getCertID8();
		final byte[] sdwRecipient = CertificateManager.get(sdwCertName).getCertID8();
		final byte[] uknRecipient = uknPubCert.getCertID8();
		assertNotNull(sdcRecipient);
		assertNotNull(sdwRecipient);
		assertNotNull(uknRecipient);
		final byte[][] recipients = { sdwRecipient, uknRecipient, sdcRecipient };
		
		if ( hasValidRecipient )			// negative test case
			recipients[2] = recipients[0];	// replace SDC with SDW to trigger failure to decrypt
		
		// Save client's CertID8 to use for verification later in the test
		byte[] clnCertID8 = CertificateManager.get(clnCertName).getCertID8();
		
		// finish initialization of the client side
		IEEE1609p2Message.setSelfCertificateFriendlyName(clnCertName);
		
		//
		// Send messages
		//
		
		final int psid = 0xcafe;
		// Prepare
		IEEE1609p2Message msgSend = new IEEE1609p2Message(cryptoProvider);
		msgSend.setPSID(psid);
		// Create signed ServiceRequest in 1609.2 envelope and send it
		byte[] signedServiceRequest = msgSend.sign(serviceRequest);
		send(signedServiceRequest);
		// Create encrypted VehSitData and send it to all recipients 
		// Note that there would be potentially multiple sends but for this testing that is irrelevant
		byte[] encryptedVehSitData = msgSend.encrypt(vehSitData, recipients);
		send(signedServiceRequest);
		
		//
		// SDC side certificate store setup
		//
		
		// Begin with an empty store
		CertificateManager.clear();
		
		// We must have CA certificate in the store in order to load any other certificates
		TestCertificateStore.load(cryptoProvider, caCertName);
		
		// Load full SDC certificates to the store
		TestCertificateStore.load(cryptoProvider, sdcCertName);
		assertNotNull(CertificateManager.get(sdcCertName));
		
		// Add public SDW certificate to the store
		TestCertificateStore.load(cryptoProvider, sdwCertName);
		assertNotNull(CertificateManager.get(sdwCertName));
		
		// finish initialization of the SDC side
		IEEE1609p2Message.setSelfCertificateFriendlyName(sdcCertName);
		
		//
		// Pretend that we received the messages
		// 

		// we do not have client's private certificate on SDC/SDW side
		assertNull(CertificateManager.get(clnCertID8));

		// decode signed ServiceRequest message
		IEEE1609p2Message msgRecv = IEEE1609p2Message.parse(signedServiceRequest, cryptoProvider);
		byte[] recvServiceRequest = msgRecv.getPayload();
		log.debug(Hex.encodeHexString(recvServiceRequest));
		assertTrue(Arrays.equals(serviceRequest, recvServiceRequest));
		assertEquals(psid, (int)msgRecv.getPSID());
		assertEquals(MsgSignerIDType.Certificate.getValue(), msgRecv.getSignerIDType().getValue());
		// client's certificate was added to the certificate store
		assertNotNull(CertificateManager.get(clnCertID8));

		// decode, validate, and decrypt encrypted VehSitData message
		try {
			msgRecv = IEEE1609p2Message.parse(encryptedVehSitData, cryptoProvider);
		} catch (MessageException ex ) {
			log.error("Error parsing 1609.2 message. Reason: " + ex.getMessage());
			assertTrue("Parsing succeeds if a valid recipient is present", hasValidRecipient);
			return;
		}
		assertEquals(MsgSignerIDType.DigestEcdsap256.getValue(), msgRecv.getSignerIDType().getValue());
		byte[] recvVehSitData = msgRecv.getPayload();
		log.debug(Hex.encodeHexString(recvVehSitData));
		assertTrue(Arrays.equals(vehSitData, recvVehSitData));
		// check that generation time is not in the future
		// if we change generation time to expiration time as per standard then we reverse the check
		long generationTime = msgRecv.getGenerationTime().getTime();
		assertTrue(generationTime < new Date().getTime());

	}
	
	/**
	 * Loads full certificate, then creates public certificate from it and puts in the store
	 * @param cryptoProvider cryptographic provider to use
	 * @param certName certificate name
	 * @throws DecoderException  if certificate decoding from HEX string fails
	 * @throws CertificateException if recipient certificate parsing fails
	 * @throws IOException  if certificate load fails
	 * @throws CryptoException  if symmetric encryption fails
	 */
	private void loadPublicCertificate(CryptoProvider cryptoProvider, String certName) throws DecoderException, CertificateException, IOException, CryptoException {
		// load full certificate, capture the certificate but remove it from the store
		TestCertificateStore.load(cryptoProvider, certName);
		Certificate priCert = CertificateManager.get(certName);
		assertNotNull(priCert);
		assertNotNull(priCert.getEncryptionPrivateKey());
		assertNotNull(priCert.getSigningPrivateKey());
		CertificateManager.remove(certName);
		assertNull(CertificateManager.get(certName));
		assertNull(CertificateManager.get(priCert.getCertID8()));
		// create public certificate from full certificate and add it to the store
		Certificate pubCert = Certificate.fromBytes(cryptoProvider, priCert.getBytes());
		assertNull(pubCert.getEncryptionPrivateKey());
		assertNull(pubCert.getSigningPrivateKey());
		CertificateManager.put(certName, pubCert);
	}
	
	byte[] getSdcRecipient() {
		Certificate sdc = CertificateManager.get("Self");
		assertNotNull(sdc);
		return sdc.getCertID8();
	}

	private void send(byte[] bytes) {
		log.debug(Hex.encodeHexString(bytes));
	}
	
	private void receive(byte[] msgBytes, byte[] sentPayload) throws MessageException, CertificateException, VectorException, CryptoException {
		IEEE1609p2Message msg = IEEE1609p2Message.parse(msgBytes);
		byte[] payload = msg.getPayload();
		log.debug(Hex.encodeHexString(payload));
		assertTrue("Payloads match", Arrays.equals(sentPayload, payload));
	}

}
