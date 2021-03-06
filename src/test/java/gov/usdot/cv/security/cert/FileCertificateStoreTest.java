package gov.usdot.cv.security.cert;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.text.ParseException;

import gov.usdot.cv.security.clock.ClockHelperTest;
import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.msg.IEEE1609p2Message;
import gov.usdot.cv.security.msg.MessageException;
import gov.usdot.cv.security.util.UnitTestHelper;
import gov.usdot.cv.security.util.vector.VectorException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.BeforeClass;
import org.junit.Test;

public class FileCertificateStoreTest {
	static final private boolean isDebugOutput = false;
	
	private static final String certsValidDate = "Sat Feb 28 15:20:00 EDT 2015";
	
	private static final String certsFolder = "/etc/certs/";
	private static final String caCert = "ca.cert";
	private static final String raCert = "ra.cert";
	private static final String selfCert = "sdw.crt";
	private static final String selfCertKey = "sdw_key.txt";
	
	static final String encryptedMessage1   = "0202004d6f128acadd2ff79f033509e15367c2d437892fcdc900d735765948c289add5a195ecf3ad47ea2654eb4c31adb25d048d3b940e5581b6f359a2599da5cc7c48e7975d1a8463abda07df7931d21a7ff0453a1cb9501e0a7fea6583ddffbb1f2359aef500438be88179ebb95c640b83b9613cfea9b78d12220d97e114eb35fdbe916d030317dd006b610ef3c0e83e755ca33c8536626df8db25f0382181a12452ada1b5c52bba632760ea983913515b43becf74b96c252e89efe0d68a0decea6d5cd8e94e6e3cf19c64be46de30ffb22f46d70d34664ec524583776113dfe1b857a84132944dc54f0b45f15fe278de7e5d38d061637bc5d1aedfe67c2070c42a9edd9415acc685f14acd93048b887b01124907dd4ad36cb9ccb96245889ea778a05886435a609ada71b2e0852836fdd0c29cb03c892970ee66baac3971a0ed6f1cfbea2283e0d47565c52aa1a76377c7643a7f705222ef46e8868ff97ce189fec1a82a2664bfdf789e383e1b2df8f7b4cc21f4915d5b2bac3f5c47520f69162862bc1632fb6cb8d518ac36427061eb68ad0aaf7f1bd12e2b5cacc8ade7d813190d6b4b8399f8418e9a8f888bd1d8c5bc3d0d7202c7ffc779cd8d506982d27933d0f0c242505233938be42933fdee315ca41d29c80b3c3130134fff7c84937b5268890afaf546e95b526a461352ca98bf0ffed53d6b7ebf30864e3b0d747417b1fe2d5bc66c9fdaf917f54969d10380445654d66096f76bd464ecad40331770e2856790c0acf3ba2ab96ea2b06538502eccdd1b684e83c0935e64946f1b0523857eea785570eb1f21c3e1e50a809f6e3be32728a2ebc478a855df27b32c5e4e6d2de4d734327ce9492ee83977fe603436451c98e026ecbbd6a467e9d73db7653fefa53e88d8ddb4be5426a2af969f86f9607223d068710d6ac1c65ec2c58a59444efbf543a34b473a730e46219d1c4a3e7ddd3f21b6e1eaa23f34865c6722506e3f0856fcd265e56a859a115f4c9866b2690940629955ea3e73db759cee510a697ae17972b3b656b0febd2338de502a530d9839a8f346ad28f5505dfa913ed1212ea737826082e45252712de33923bf6025d77244ba70e9ca4ca9d9fa8ff362cd74b4a55182b135ebd3dbb9cfb3bd59f01dbb71cf126d30e6aa84f037e7bb43613fd6cdbc69d63d870e859e7d48491315acbd05f5151558928cd571dc7a18aff09bb5527ed01cd4f53332e8ce22800494eed69d2f4f6ef42e82bca17348283c64a970296f15446065d47b97fab931ef3349597db3c0fec6a0593cc505b63a4ceedbbbbf23c26dbe190ece4406fae66ce94ae3f8da22631701c7a91a87ccd059dc52924aa8bcc245312cbe687efee18ce68a7ed550ff5992cf166f72763dffe5b4398cf4f9ce225f973e064e0da741b33f7fefdbfd171617a907abb7e25e7b0f7e91407dcd0e0c0556c2115f32a26b28a8c8b20a0e3cfbe889ace05f7b6869343470fe20dcd66cc05c817bd575920ae2c790f64d9fb8c67196045";
	static final String encryptedMessage2   = "0202004d6f128acadd2ff79f02103f3e7c1fd84d745443f27fba71048e1fa56deadfaad61d1bc633204af8f2de012a4079ddb51a26ab474fc0c2a203e0cb2ec79feb37543a414eaa224c39c613d334ef52a45e01ebaedbd650bcccb39183ddf68ff137b9582940f234e1ab7bb6a99844d57379fce1ba2232853b83d9e22fbcada1ca6d77650ac156a90ef94cad0d2676bc66c06b07bd0c15cd9704687ef2c9c04bc2f7b9342269bec3b1f42da1c5df64f8601a36e1d511774b23bc398532e77715ab6863f09856d8fda699b09e35bdece7b740dbdcd150ed7fc91216d7210497bca4d568ffe2fcb5c76ae73ff511d3f34e50f7dcce91202d1437ef846c27c237d07f71552501404f360fb2238f244f6f695536963db1b22e7285a384d352570c85e86e1c1c3bd5db649367bd632e9b7cddc74a46c56485917bc06cfd3ee1429c3d56eb0c5d7e3121f49b5d3a284e0311d7cc7e479ae379887ce3b955a2a960fe3fe5be1fabeff2a94d813c402d25d650c7e01489d226628239a4f637c5d77fbdc20026b4febe26b683e59720d43d9625f9758a584c5517be01aadaf114477a727324dcca8c621fea82e5e0b7c39f183b1ec0e77ef1573194abbae20924ba83475f095c5c3a33f5bd3fabb97a4bbf0db9362de5e4ea2821f254f13158b507d2ebdde95087431ce5f7de2715f5cca51ac9807c0bc69ac8369b23334c8993dc04cf55791b0fa7a4975c2b940ebd7a5c05ae8797f07ee8443e25b412ddac888293ff1f4d707394736757b57cca24b21ddeb5adc83ff264f71cd1e562d6bf6b6218b5454e6cde8632a4a16eea509370f0e8f2c11e1fb69d0e2c696a03e931dbdef43de299a76a036e939ce1ba40d4a41669c1f887846373504f2cb2a86087ca283b8d86c0f774252ffd12db7dfe10a80950766ee7ffa9303d621ead5c4b8fb04aff11f453a1575ee0eefa8c08da76cf36f609082eb833eca37b883770a78839124070bef6bb29f8db0615cf77022a63ff7aced99f2c4c782b7196ff7731e01f3643d0cabf6ff084510402f9043d1af1eda9f6968ab9a900cdce6210793f1afa0f4cd6b3e547a35b98f771a868ffbe107f8ccb3ac52c25feb8ae1cec43a9d31049f4c1a091865e50dd0a3cc21a687b2a44c380a80c0664a993f8039f5c92c2412f536bbab64488a54f896b36c09bc9522b7e61c919773ae081cc1a0738a233af9e9f2df705812b33a7273699c67d73174b9c3dfc50bcbd20b0fe5c6a8151462acd68881896f8a90d8650c39a25b8b1ef73ff4a4b249f4b41be3491c58668683171fd9780fb34f13422a0f0280839bb7680390343d3dfa678c36e3e18139822a56c92f410f16e0a9ca3fbb57ca4a5d0a26608fb43b03145ccd9332b67889565ad84f8d3d440322280390d78e4d8129cc24974f5deb595d849c1d88a3771b05392b418cafbea842d17312f27cdb45a4d7de2c3acc5b87ed8a4ae0a960a42e32943955c0379d2512846c2d7143d19517947fdb5bf1332232b046222f68d1062b2";

	static final String signedServiceRequest  = "020103030205af58634513be7ffb01000103afe1000416b9eb5e14b12ade0000000102000387cd316aefef15e3f290376e7277a35c5291a0b7509fae3929d776730d6642a102ba28d4894ead081d12cc9d151ccd88de510937b775956af56d15163ba03ad77d02afe11c301a8002009a810101820400000000830400000001a405810300b6a1000140e3521b86000000f46e3dc20933d3e0901a98946543c6a742e35935ee3597ff6610cfd0093a7fc8336c771588eb5846c6f41cccbde780781e297c675d82e57f982a1483dce1e8a6";
	static final String payloadServiceResponse = "30708002009a810102820400000000830400000001a413800207df810103820107830112840123850111a524a01080041cd5572a8104b188b98082020000a11080040e65f3848104d4e0aff08202000086204c6519daf1c05016751dab9837fc970d6550f2fe67e1c303cbf807c89ce63fdc";
	static final String signedServiceResponse  = "020103030205af58634513be7ffb01000103afe1000416b9eb5e14b12ade0000000102000387cd316aefef15e3f290376e7277a35c5291a0b7509fae3929d776730d6642a102ba28d4894ead081d12cc9d151ccd88de510937b775956af56d15163ba03ad77d02afe17230708002009a810102820400000000830400000001a413800207df810103820107830112840123850111a524a01080041cd5572a8104b188b98082020000a11080040e65f3848104d4e0aff08202000086204c6519daf1c05016751dab9837fc970d6550f2fe67e1c303cbf807c89ce63fdc000140e78311af600000c0f4b3d645fdf7f4eac5282ea5d8dfb503ec79243be0cc6f75a598be45858050e5b299c8396278adb2e802ed121064c0a54c430e01741ab1f31c59c62f26e62a";

	static final String encryptedFailedVsdMessage = "0202004d6f128acadd2ff79f0202173e6cf69a9de4dc74f20b4f80a501c5717c2c8243ce778b218151f145a74633c0b5943b8cff14b4a7a06aed504420b7ae716efab57d14fe72524ffdd179fb095096b4948d27917aff36d96e35b89e83ddf5b1b12449068eeb1ae1aafc99fdd44d37fa32d3b9569f5c140b34b3b5c0567731822e77168b9fd4bcf645813479bdbaf340ba7129f919359a1621805481fbbbfe3b963b83c0d17191eb0abebf83540f7ff653dc5a60028c72043a866e6a7480ab5d042853903937f99ca93cd722be497e02e7d08046808b68453cdbbd42bbc96d839eaff10efbeff92d55027a71e02f03e9a84b211247299913c9b564b7718a68f0ab8e715196bd937c29a6901db6cb990458af30ec27bbf15765fd883a37756a78802c019611b973b9fbc8c9d3e67810e526d6a6544eb652daefb5d405833bc0d2e348b52f71ab32ce7c18e422a63aac73137b72dd4a5bccb444b6b60875d940698b88210c4d23639defb4d4d2acd4ff5715caf240774c221e0cb074f92224a53324ea5f451166967742aac493634a93fbfbcb2600be9877794b02ba5a851305f4da315e510bf4fa791950f07f10ecac9dcf9a8419864e270306213015a42e7e12dc2cd8ed3cfe5ae73912de244ef318a32741f1c1ee40717a30ec3078a5e80ae8fb5e029379280c380c67c8880acac8b292402b6b7fa5873a9457059a1e69063e07866a1727dc3c3ed91158dc45adcd85c8e6dcefa3fe30ebd29e3d1303a7fc4738043b60458b6b0f772838440b5e65d8eb5e2ff7a473179a93d15504dac7e846e9dbfc5e3610c2d2b3b7b8443cf0308cf1da46806b6e4e538f86c66c388ffa0474ab0850b4491d16eb72e22b2f3d2025d09d9b38af6dbb171a2f470a0ee79d0a49372e292915053856c75172ceafea735bc2dbe2220bef7668e151c2c51a93bc582a402f4dd8d69b0c465ad3f9b33356e8751a607eb8ebf7f571c5ad7406233569c59441fc00176d0a19f3b55cbebcde223dc87e458bee4aad0879d38d14d6648b8b047a8785eca9ed75c2aebee56d1a9e442189f46378d113d4a609e489cd9af33c1a777bde036d951e030c19d823b53b92027f8062ec3e83767e5c5c41e87800069f3081a984afacea34b092f3879c02b530fcf365af7f13eb33acb2eb6c7b432e69301b2128c4eba655f6e18d2d18f577479632d1820f7bce7a45f3dce475fb9ebbcc1b5b223e75fef981c7d6883e367093380c223cf47409676287adce4b88d6a52d5774f118446b5074baf49e81ab610bee467510a5451f1327643f8fc2669fda14698824cb2cae0cdecf765ac281d3aae1754e9e8b64387a41033675d8459aa63b099441a99259206971eba36b79b94e7002e9dd569f46f8860fcb0ae9cd51e06038b4e2988ec880cd0928983a7ca4492a1d3721940ca69e14c013520903b52c66c10323fbd554ac0bd00a87e98e901af9cbf6877c0eecafab832aefdeb0c18976424be7735848ca1a4da2c9ee1d496a10b7b8aa891c0817";
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
		ClockHelperTest.setNow(certsValidDate);
		CertificateManager.clear();
	}
	
	@Test @org.junit.Ignore
	public void testPublicCertificateLoad() throws DecoderException, CertificateException, IOException, CryptoException {
		FileCertificateStore.load(new CryptoProvider(), "CA", certsFolder + caCert);
		Certificate cert = CertificateManager.get("CA");
		assertNotNull(cert);
		assertNotNull(cert.getEncryptionPublicKey());
		assertNotNull(cert.getSigningPublicKey());
		assertNull(cert.getEncryptionPrivateKey());
		assertNull(cert.getSigningPrivateKey());
	}
	
	@Test @org.junit.Ignore
	public void testFullCertificateLoad() throws DecoderException, CertificateException, IOException, CryptoException {
		FileCertificateStore.load(new CryptoProvider(), "Self", certsFolder + selfCert, certsFolder + selfCertKey);
		Certificate cert = CertificateManager.get("Self");
		assertNotNull(cert);
		assertNotNull(cert.getEncryptionPublicKey());
		assertNotNull(cert.getSigningPublicKey());
		assertNotNull(cert.getEncryptionPrivateKey());
		assertNotNull(cert.getSigningPrivateKey());
	}
	
	@Test @org.junit.Ignore
	public void testValidateAndLog() throws ParseException, DecoderException, CertificateException, IOException, CryptoException, MessageException, VectorException {
		CertificateManager.clear();
		CryptoProvider cryptoProvider = new CryptoProvider();
		FileCertificateStore.load(cryptoProvider, "CA", certsFolder + caCert);
		FileCertificateStore.load(cryptoProvider, "RA", certsFolder + raCert);
		FileCertificateStore.load(cryptoProvider, "Self", certsFolder + selfCert, certsFolder + selfCertKey);
		
		for( int i = 0; i < 3; i++ ) {
			decrypt(signedServiceRequest, cryptoProvider);
			encrypt(payloadServiceResponse, cryptoProvider);
			decrypt(encryptedFailedVsdMessage, cryptoProvider);
		}

		CertificateManager.clear();
	}
	
	private void decrypt(String encryptedMessage, CryptoProvider cryptoProvider) throws DecoderException, MessageException, CertificateException, VectorException, CryptoException {
		byte[] encryptedMessageBytes = Hex.decodeHex(encryptedMessage.toCharArray());
		IEEE1609p2Message msgRecv = IEEE1609p2Message.parse(encryptedMessageBytes, cryptoProvider);
		byte[] recvEncryptedMessage = msgRecv.getPayload();
		assertNotNull(recvEncryptedMessage);
	}
	
	private byte[] encrypt(String payloadString, CryptoProvider cryptoProvider) throws VectorException, CertificateException, DecoderException {
		final int Psid = 0x2fe1;
		byte[] payloadBytes = Hex.decodeHex(payloadString.toCharArray());
		IEEE1609p2Message msg = new IEEE1609p2Message(cryptoProvider);
		msg.setPSID(Psid);
		return  msg.sign(payloadBytes);
	}
}
