package gov.usdot.cv.security.cert.psid;

import java.nio.ByteBuffer;

import gov.usdot.cv.security.util.PSIDHelper;
import gov.usdot.cv.security.util.vector.EncodableVectorItem;
import gov.usdot.cv.security.util.vector.VectorException;

/**
 * Vector of PsidSspVectorItem items
 */
public class PsidPriorityVectorItem  implements EncodableVectorItem<PsidPriorityVectorItem> {

	private int psid;
	private int maxPriority;
	
	public PsidPriorityVectorItem(int psid, int maxPriority) {
		this.psid = psid;
		this.maxPriority = maxPriority;
	}
	
	/**
	 * Retrieves psid value
	 * @return value of this psid item
	 */
	public int getPsid() { 
		return psid; 
	}
	
	/**
	 * Retrieves max priority
	 * @return max priority value
	 */
	public int getMaxPriority() { 
		return maxPriority; 
	}
	
	@Override
	public int getLength() {
		return PSIDHelper.calculateLength(psid) + 4;
	}

	@Override
	public void encode(ByteBuffer byteBuffer) throws VectorException {
		PSIDHelper.encodePSID(byteBuffer, psid);
		byteBuffer.putInt(maxPriority);
	}

	@Override
	public PsidPriorityVectorItem decode(ByteBuffer byteBuffer) throws VectorException {
		psid = PSIDHelper.decodePSID(byteBuffer);
		maxPriority = byteBuffer.getInt();
		return new PsidPriorityVectorItem(psid, maxPriority);
	}
	
	/**
	 * Returns a string representation of the PsidSspVectorItem
	 */
	@Override
	public String toString() {
		return String.format("psid: 0x%x (%d), priority: 0x%x (%d)", psid, psid, maxPriority, maxPriority);
	}

}
