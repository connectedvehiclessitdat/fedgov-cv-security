package gov.usdot.cv.security.type;

import java.util.HashMap;
import java.util.Map;

/**
 * 6.2.16 PKAlgorithm
 */
public enum SignatureAlgorithm {
	EcdsaNistp224WithSha224(0),
	EcdsaNistp256WithSha256(1),
	EciesNistp256(2);
	
	private final int signatureAlgorithm;

	private static Map<Integer, SignatureAlgorithm> map = new HashMap<Integer, SignatureAlgorithm>();
	
	static {
		for( SignatureAlgorithm value : SignatureAlgorithm.values() )
			map.put(value.signatureAlgorithm, value);
	}

	private SignatureAlgorithm(int pkAlgorithm) {
		this.signatureAlgorithm = pkAlgorithm;
	}
	
	public int getValue() {
		return signatureAlgorithm;
	}
	
	public static SignatureAlgorithm valueOf(int value ) {
		return map.get(value);
	}
}
