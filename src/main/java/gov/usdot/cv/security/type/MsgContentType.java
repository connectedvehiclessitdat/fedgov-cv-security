package gov.usdot.cv.security.type;

import java.util.HashMap;
import java.util.Map;

/**
 * 6.2.2 ContentType (partial): IEEE 1609.2 Message content type  
 */
public enum MsgContentType {
	Unsecured(0),
	Signed(1),
	Encrypted(2);
	
	private final int contentType;

	private static Map<Integer, MsgContentType> map = new HashMap<Integer, MsgContentType>();
	
	static {
		for( MsgContentType value : MsgContentType.values() )
			map.put(value.contentType, value);
	}

	private MsgContentType(int contentType) {
		this.contentType = contentType;
	}
	
	public int getValue() {
		return contentType;
	}
	
	public static MsgContentType valueOf(int value ) {
		return map.get(value);
	}
}
