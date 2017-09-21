package gov.usdot.cv.security.cert.psid;

import gov.usdot.cv.security.type.ArrayType;
import gov.usdot.cv.security.util.vector.OpaqueVariableLengthVector;
import gov.usdot.cv.security.util.vector.VectorException;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

/**
 *  PsidPriorityArray (6.3.11) helper
 */
public class PsidPriorityArray {
	
	private static final Logger log = Logger.getLogger(PsidPriorityArray.class);
	
	private ArrayType type;
	private List<PsidPriorityVectorItem> permissionsList;
	private byte[] otherPermissions;
	
	/**
	 * default constructor
	 */
	private PsidPriorityArray() {
	}
	
	/**
	 * Package scoped constructor intended for supporting unit tests
	 * @param type specifies whether an array is specified locally or obtained by reference
	 * @param permissionsList permissions list 
	 * @param otherPermissions unknown permissions list
	 */
	PsidPriorityArray(ArrayType type, List<PsidPriorityVectorItem> permissionsList, byte[] otherPermissions) {
		this.type = type;
		this.permissionsList = permissionsList;
		this.otherPermissions = otherPermissions;
		switch( this.type ) {
		case FromIssuer:
			// inherited from the issuing certificates
			break; 
		case Specified:
			if ( permissionsList == null )
				this.permissionsList = Arrays.asList(new PsidPriorityVectorItem[0]);
			break;
		case Unknown:
			if ( otherPermissions == null )
				this.otherPermissions = new byte[0];
			break;
		}
	}
	
	/**
	 * Decoded byte buffer
	 * @param byteBuffer to decode
	 * @return decode PsidArray instance
	 * @throws VectorException if decoding fails
	 */
	public static PsidPriorityArray decode(ByteBuffer byteBuffer) throws VectorException {
		PsidPriorityArray psidArray = new PsidPriorityArray();
		int arrayType = byteBuffer.get() & 0xFF;
		psidArray.type = ArrayType.valueOf(arrayType);
		
		switch( psidArray.getType() ) {
		case FromIssuer:
			// inherited from the issuing certificates
			break; 
		case Specified:
			PsidPriorityVector psidPriorityVector = new PsidPriorityVector();
			psidPriorityVector.decode(byteBuffer, new PsidPriorityVectorItem(0,0));
			final int psidPriorityVectorSize = psidPriorityVector.size();
			psidArray.permissionsList = new ArrayList<PsidPriorityVectorItem>(psidPriorityVectorSize);
			for (PsidPriorityVectorItem psidPriority : psidPriorityVector )
				psidArray.permissionsList.add(psidPriority);
			break;
		case Unknown:
			psidArray.otherPermissions = OpaqueVariableLengthVector.decode(byteBuffer);
			break;
		default:
			log.error("Unsupported array type");
		}
		return psidArray;
	}
	
	/**
	 * Encodes specified Psid array
	 * @param byteBuffer buffer to encode into
	 * @param psidArray Psid array to encode 	
	 * @throws VectorException if encoding fails
	 */
	public static void encode(ByteBuffer byteBuffer, PsidPriorityArray psidArray) throws VectorException {
		byteBuffer.put((byte)psidArray.type.getValue());
		if ( psidArray.permissionsList != null ) {
			PsidPriorityVector psidPriorityVector = new PsidPriorityVector();
			for( PsidPriorityVectorItem psidPriorityItem : psidArray.permissionsList)
				psidPriorityVector.add(psidPriorityItem);
			psidPriorityVector.encode(byteBuffer);
		} else if (psidArray.otherPermissions != null ) {
			OpaqueVariableLengthVector.encode(byteBuffer, psidArray.otherPermissions);
		}
	}
	
	/**
	 * Retrieves type
	 * @return type value
	 */
	public ArrayType getType() {
		return type;
	}

	/**
	 * Retrieves permissions list
	 * @return permissions list value
	 */
	public List<PsidPriorityVectorItem> getPermissionsList() {
		return permissionsList;
	}

	/**
	 * Retrieves other permissions
	 * @return other permissions value
	 */
	public byte[] getOtherPermissions() {
		return otherPermissions;
	}
	
	/**
	 * Returns a string representation of the PsidPriorityArray
	 */
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(String.format("Type: %s (%d)", type, type.getValue()));
		switch(type) {
		case Specified:
			if ( permissionsList != null && permissionsList.size() > 0) {
				sb.append("; permissions: ");
				boolean first = true;
				for( PsidPriorityVectorItem priority : permissionsList) {
					if ( first )
						first = !first;
					else
						sb.append("; ");
					sb.append(priority);
				}
			}
			break;
		case FromIssuer:
			break;
		case Unknown:
			if ( otherPermissions != null && otherPermissions.length > 0 ) {
				sb.append("; permissions: ").append(Hex.encodeHexString(otherPermissions));
			}
			break;
		}
		return sb.toString();
	}

}
