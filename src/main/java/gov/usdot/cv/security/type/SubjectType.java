package gov.usdot.cv.security.type;

import java.util.HashMap;
import java.util.Map;

/**
 * 6.3.3 SubjectType
 */
public enum SubjectType {
	secDataExchAnonymous(0), 
    secDataExchIdentifiedNotLocalized (1),
    secDataExchIdentifiedLocalized (2), 
    secDataExchCsr (3),
    wsa (4), 
    wsaCsr (5),
    secDataExchCa(6), 
    wsaCa (7), 
    crlSigner(8),
    secDataExchRa(9),	// not standard 
    rootCa (255);
	
	private final int subjectType;

	private static Map<Integer, SubjectType> map = new HashMap<Integer, SubjectType>();
	
	static {
		for( SubjectType value : SubjectType.values() )
			map.put(value.subjectType, value);
	}

	private SubjectType(int subjectType) {
		this.subjectType = subjectType;
	}
	
	public int getValue() {
		return subjectType;
	}
	
	public static SubjectType valueOf(int value ) {
		return map.get(value);
	}
}

