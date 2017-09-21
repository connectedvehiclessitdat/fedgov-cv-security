package gov.usdot.cv.security.cert.psid;

import java.nio.ByteBuffer;

import gov.usdot.cv.security.util.PSIDHelper;
import gov.usdot.cv.security.util.vector.EncodableVectorItem;
import gov.usdot.cv.security.util.vector.VectorException;

/**
 * Vector of PsidVectorItem items
 */
public class PsidVectorItem  implements EncodableVectorItem<PsidVectorItem> {

	private int psid;
	
	public PsidVectorItem(int psid) {
		this.psid = psid;
	}
	
	/**
	 * Retrieves psid value
	 * @return value of this psid item
	 */
	public int get() { 
		return psid; 
	}
	
	@Override
	public int getLength() {
		return PSIDHelper.calculateLength(psid);
	}

	@Override
	public void encode(ByteBuffer byteBuffer) throws VectorException {
		PSIDHelper.encodePSID(byteBuffer, psid);
	}

	@Override
	public PsidVectorItem decode(ByteBuffer byteBuffer) throws VectorException {
		psid = PSIDHelper.decodePSID(byteBuffer);
		return new PsidVectorItem(psid);
	}

}
