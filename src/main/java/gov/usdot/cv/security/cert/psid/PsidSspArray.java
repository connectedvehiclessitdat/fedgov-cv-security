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
 *  PsidSspArray (6.3.23) helper
 */
public class PsidSspArray {
	
	private static final Logger log = Logger.getLogger(PsidSspArray.class);
	
	private ArrayType type;
	private List<PsidSspVectorItem> permissionsList;
	private byte[] otherPermissions;
	
	/**
	 * default constructor
	 */
	private PsidSspArray() {
	}
	
	/**
	 * Package scoped constructor intended for supporting unit tests
	 * @param type specifies whether an array is specified locally or obtained by reference
	 * @param permissionsList permissions list 
	 * @param otherPermissions unknown permissions list
	 */
	PsidSspArray(ArrayType type, List<PsidSspVectorItem> permissionsList, byte[] otherPermissions) {
		this.type = type;
		this.permissionsList = permissionsList;
		this.otherPermissions = otherPermissions;
		switch( this.type ) {
		case FromIssuer:
			// inherited from the issuing certificates
			break; 
		case Specified:
			if ( permissionsList == null )
				this.permissionsList = Arrays.asList(new PsidSspVectorItem[0]);
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
	public static PsidSspArray decode(ByteBuffer byteBuffer) throws VectorException {
		PsidSspArray psidArray = new PsidSspArray();
		int arrayType = byteBuffer.get() & 0xFF;
		psidArray.type = ArrayType.valueOf(arrayType);
		
		switch( psidArray.getType() ) {
		case FromIssuer:
			// inherited from the issuing certificates
			break; 
		case Specified:
			PsidSspVector psidSspVector = new PsidSspVector();
			psidSspVector.decode(byteBuffer, new PsidSspVectorItem(0, null));
			final int psidSspVectorSize = psidSspVector.size();
			psidArray.permissionsList = new ArrayList<PsidSspVectorItem>(psidSspVectorSize);
			for (PsidSspVectorItem psidSsp : psidSspVector )
				psidArray.permissionsList.add(psidSsp);
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
	public static void encode(ByteBuffer byteBuffer, PsidSspArray psidArray) throws VectorException {
		byteBuffer.put((byte)psidArray.type.getValue());
		if ( psidArray.permissionsList != null ) {
			PsidSspVector psidSspVector = new PsidSspVector();
			for( PsidSspVectorItem psidSspItem : psidArray.permissionsList)
				psidSspVector.add(psidSspItem);
			psidSspVector.encode(byteBuffer);
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
	public List<PsidSspVectorItem> getPermissionsList() {
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
	 * Returns a string representation of the PsidSspArray
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
				for( PsidSspVectorItem ssp : permissionsList) {
					if ( first )
						first = !first;
					else
						sb.append("; ");
					sb.append(ssp);
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
