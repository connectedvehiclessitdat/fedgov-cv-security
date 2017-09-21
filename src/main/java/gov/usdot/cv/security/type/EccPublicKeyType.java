package gov.usdot.cv.security.type;

import java.util.HashMap;
import java.util.Map;

/**
 * 6.2.19 EccPublicKeyType
 */
public enum EccPublicKeyType {
	XCoordinateOnly (0),
	CompressedLsbY0 (2),
	CompressedLsbY1 (3),
	Uncompressed(4);
	
	private final int eccPublicKey;

	private static Map<Integer, EccPublicKeyType> map = new HashMap<Integer, EccPublicKeyType>();
	
	static {
		for( EccPublicKeyType value : EccPublicKeyType.values() )
			map.put(value.eccPublicKey, value);
	}

	private EccPublicKeyType(int contentType) {
		this.eccPublicKey = contentType;
	}
	
	public int getValue() {
		return eccPublicKey;
	}
	
	public static EccPublicKeyType valueOf(int value ) {
		return map.get(value);
	}

}
