package gov.usdot.cv.security.type;

import java.util.HashMap;
import java.util.Map;

/**
 * 6.2.5 SignerIdentifierType (partial)
 */
public enum MsgSignerIDType {
	Self(0),
	DigestEcdsap224(1),
	DigestEcdsap256(2),
	Certificate(3);
	
	private final int signerIDType;

	private static Map<Integer, MsgSignerIDType> map = new HashMap<Integer, MsgSignerIDType>();
	
	static {
		for( MsgSignerIDType value : MsgSignerIDType.values() )
			map.put(value.signerIDType, value);
	}

	private MsgSignerIDType(int contentType) {
		this.signerIDType = contentType;
	}
	
	public int getValue() {
		return signerIDType;
	}
	
	public static MsgSignerIDType valueOf(int value ) {
		return map.get(value);
	}

}
