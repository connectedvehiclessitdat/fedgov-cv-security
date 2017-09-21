package gov.usdot.cv.security.type;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

/**
 * 6.3.8 SubjectTypeFlags
 */
public enum SubjectTypeFlags {
	secDataExchAnonymous				(1<<0), 
    secDataExchIdentifiedNotLocalized 	(1<<1),
    secDataExchIdentifiedLocalized 		(1<<2), 
    secDataExchCsr 						(1<<3),
    wsa 								(1<<4), 
    wsaCsr 								(1<<5),
    secDataExchCa						(1<<6), 
    wsaCa 								(1<<7), 
    crlSigner							(1<<8); 
	
	private final int subjectTypeFlags;

	private static Map<Integer, SubjectTypeFlags> map = new HashMap<Integer, SubjectTypeFlags>();
	
	static {
		for( SubjectTypeFlags value : SubjectTypeFlags.values() )
			map.put(value.subjectTypeFlags, value);
	}

	private SubjectTypeFlags(int subjectType) {
		this.subjectTypeFlags = subjectType;
	}
	
	public int getValue() {
		return subjectTypeFlags;
	}
	
	public static SubjectTypeFlags valueOf(int value ) {
		return map.get(value);
	}
	
	public static EnumSet<SubjectTypeFlags> create(int subjectTypeFlagsValue) {
		EnumSet<SubjectTypeFlags> subjectTypeFlags = EnumSet.noneOf(SubjectTypeFlags.class);
		for( SubjectTypeFlags flag : SubjectTypeFlags.values())
			if ( (flag.getValue() & subjectTypeFlagsValue) != 0 )
				subjectTypeFlags.add(flag);
		return subjectTypeFlags;
	}
	
	public static boolean anyOf(EnumSet<SubjectTypeFlags> enumSet, SubjectTypeFlags ... flags) {
		for( SubjectTypeFlags flag : flags )
			if ( enumSet.contains(flag) )
				return true;
		return false;
	}
}

