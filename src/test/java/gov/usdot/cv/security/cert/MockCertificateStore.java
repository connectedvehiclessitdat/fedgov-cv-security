package gov.usdot.cv.security.cert;

import java.nio.ByteBuffer;
import java.util.Date;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.crypto.ECDSAProvider;
import gov.usdot.cv.security.util.ByteBufferHelper;

public class MockCertificateStore {
	
	static public void addTestCertificates() {
		addCertificates("CA", "CA-private");
		addCertificates("Self-public", "Self-private");
		addCertificates("Client-public", "Client-private");
	}
	
	static public void addCertificates(String publicCertificateName, String privateCertificateName) {
		Certificate[] certificates = createCertificates();
		CertificateManager.put(privateCertificateName, certificates[0]);
		CertificateManager.put(publicCertificateName,  certificates[1]);
	}
	
	static public Certificate[] createCertificates() {
		CryptoProvider cryptoProvider = new CryptoProvider();
		MockCertificate privateCertificate = new MockCertificate(cryptoProvider);
		MockCertificate publicCertificate  = new MockCertificate(privateCertificate);
		return new MockCertificate[] { privateCertificate, publicCertificate };
	}
	
	public static class MockCertificate extends Certificate {
		
		protected boolean isPrivateCertificate;
		protected final ECDSAProvider ecdsaProvider;
		
		/**
		 * Create private mock certificate
		 * @param cryptoProvider to use for certificate generation
		 */
		protected MockCertificate(CryptoProvider cryptoProvider) {
			super(cryptoProvider);
			isPrivateCertificate = true;
			ecdsaProvider = cryptoProvider.getSigner();
			
			AsymmetricCipherKeyPair signingKeyPair = ecdsaProvider.generateKeyPair();
			signingPrivateKey = (ECPrivateKeyParameters)signingKeyPair.getPrivate();
			signingPublicKey = (ECPublicKeyParameters)signingKeyPair.getPublic();
			
			AsymmetricCipherKeyPair encryptKeyPair = ecdsaProvider.generateKeyPair();
			encryptionPrivateKey = (ECPrivateKeyParameters)encryptKeyPair.getPrivate();
			this.encryptionPublicKey = (ECPublicKeyParameters)encryptKeyPair.getPublic();
		}
		
		/**
		 * Create public mock certificate from a private certificate
		 * @param privateCertificate to copy public keys from
		 */
		protected MockCertificate(MockCertificate privateCertificate) {
			super(privateCertificate.cryptoProvider);
			isPrivateCertificate = false;
			ecdsaProvider = privateCertificate.ecdsaProvider;
			encryptionPublicKey = privateCertificate.getEncryptionPublicKey();
			signingPublicKey = privateCertificate.getSigningPublicKey();
		}
		
		/**
		 * Create mock certificate from serialized bytes
		 * @param cryptoProvider to assign to this certificate
		 * @param byteBuffer bytes to serialize from
		 */
		protected MockCertificate(CryptoProvider cryptoProvider, ByteBuffer byteBuffer) {
			super(cryptoProvider);
			ecdsaProvider = cryptoProvider.getSigner();
			byte certCount = byteBuffer.get();
			isPrivateCertificate = certCount == 4;
			if ( isPrivateCertificate ) {
				signingPrivateKey = ecdsaProvider.decodePrivateKey(byteBuffer);
				encryptionPrivateKey = ecdsaProvider.decodePrivateKey(byteBuffer);
			}
			signingPublicKey = 	ecdsaProvider.decodePublicKey(byteBuffer);
			encryptionPublicKey = ecdsaProvider.decodePublicKey(byteBuffer);
		}
		
		/**
		 * Create certificate from bytes
		 * @param cryptoProvider  to assign to this certificate
		 * @param bytes to serialize from
		 * @return Mock Certificate
		 */
		static public Certificate fromBytes(CryptoProvider cryptoProvider, byte[] bytes) {
			return fromBytes(cryptoProvider, ByteBuffer.wrap(bytes));
		}
		
		/**
		 * Create certificate from bytes
		 * @param cryptoProvider  to assign to this certificate
		 * @param byteBuffer bytes to serialize from
		 * @return Mock Certificate
		 */
		static public Certificate fromBytes(CryptoProvider cryptoProvider, ByteBuffer byteBuffer) {
			return new MockCertificate(cryptoProvider, byteBuffer);
		}
		
		/**
		 * Serializes mock certificate to bytes
		 */
		@Override
		public byte[] getBytes() {
			final byte certCount = (byte)(isPrivateCertificate ? 4 : 2);
			ByteBuffer bb = ByteBuffer.allocate(1 + (ECDSAProvider.ECDSAPublicKeyEncodedLength)*certCount);
			bb.put(certCount);
			if ( isPrivateCertificate ) {
				ecdsaProvider.encodePrivateKey(bb, signingPrivateKey);
				ecdsaProvider.encodePrivateKey(bb, encryptionPrivateKey);
			}
			ecdsaProvider.encodePublicKey(bb, signingPublicKey);
			ecdsaProvider.encodePublicKey(bb, encryptionPublicKey);
			return ByteBufferHelper.copyBytes(bb);
		}
		
		@Override
		public boolean isValid() {
			return true;
		}

		@Override
		public Date getExpiration() {
			final long thisTimeNextWeek = System.currentTimeMillis() + 1000*60*60*24*7;
			return new Date( thisTimeNextWeek );
		}
	}

}
