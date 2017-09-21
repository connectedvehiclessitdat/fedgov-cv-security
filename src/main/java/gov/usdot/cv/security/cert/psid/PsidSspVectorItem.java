package gov.usdot.cv.security.cert.psid;

import java.nio.ByteBuffer;

import org.apache.commons.codec.binary.Hex;

import gov.usdot.cv.security.util.PSIDHelper;
import gov.usdot.cv.security.util.vector.EncodableVectorItem;
import gov.usdot.cv.security.util.vector.OpaqueVariableLengthVector;
import gov.usdot.cv.security.util.vector.VectorException;

/**
 * Vector of PsidSspVectorItem items
 */
public class PsidSspVectorItem  implements EncodableVectorItem<PsidSspVectorItem> {

	private int psid;
	private byte[] ssp;	// service specific permissions
	
	public PsidSspVectorItem(int psid, byte[] ssp) {
		this.psid = psid;
		this.ssp = ssp;
	}
	
	/**
	 * Retrieves psid value
	 * @return value of this psid item
	 */
	public int getPsid() { 
		return psid; 
	}
	
	/**
	 * Retrieves Service Specific Permissions (SSP)
	 * @return service specific permissions value
	 */
	public byte[] getSsp() { 
		return ssp; 
	}
	
	@Override
	public int getLength() {
		// "The Service Specific Permissions (SSP) field shall have a length no more than 31 octets." Thus its <var> length is always 1 byte
		return PSIDHelper.calculateLength(psid) + 1 + (ssp != null ? ssp.length : 0);
	}

	@Override
	public void encode(ByteBuffer byteBuffer) throws VectorException {
		PSIDHelper.encodePSID(byteBuffer, psid);
		OpaqueVariableLengthVector.encode(byteBuffer, ssp);
	}

	@Override
	public PsidSspVectorItem decode(ByteBuffer byteBuffer) throws VectorException {
		psid = PSIDHelper.decodePSID(byteBuffer);
		ssp  = OpaqueVariableLengthVector.decode(byteBuffer);
		return new PsidSspVectorItem(psid, ssp);
	}
	
	/**
	 * Returns a string representation of the PsidSspVectorItem
	 */
	@Override
	public String toString() {
		return String.format("psid: 0x%x (%d), ssp: %s", psid, psid, ssp != null ? Hex.encodeHexString(ssp) : "null" );
	}
}
