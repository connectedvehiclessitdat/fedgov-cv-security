package gov.usdot.cv.security.type;

import java.util.HashMap;
import java.util.Map;

/**
 * 6.3.10 ArrayType
 *
 */
public enum ArrayType {
	FromIssuer(0),
	Specified(1),
	Unknown(255);
	
	private final int arrayType;

	private static Map<Integer, ArrayType> map = new HashMap<Integer, ArrayType>();
	
	static {
		for( ArrayType value : ArrayType.values() )
			map.put(value.arrayType, value);
	}

	private ArrayType(int contentType) {
		this.arrayType = contentType;
	}
	
	public int getValue() {
		return arrayType;
	}
	
	public static ArrayType valueOf(int value ) {
		return map.get(value);
	}
}
