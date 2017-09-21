package gov.usdot.cv.security.type;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

/**
 * 6.3.4 CertificateContentFlags
 */
public enum CertificateContentFlags {
	useStartValidity 	(1<<0),
	lifetimeIsDuration	(1<<1),
	encryptionKey 		(1<<2);
	
	private final int contentFlags;

	private static Map<Integer, CertificateContentFlags> map = new HashMap<Integer, CertificateContentFlags>();
	
	static {
		for( CertificateContentFlags value : CertificateContentFlags.values() )
			map.put(value.contentFlags, value);
	}

	private CertificateContentFlags(int contentType) {
		this.contentFlags = contentType;
	}
	
	public int getValue() {
		return contentFlags;
	}
	
	public static CertificateContentFlags valueOf(int value ) {
		return map.get(value);
	}
	
	public static EnumSet<CertificateContentFlags> create(int subjectTypeFlagsValue) {
		EnumSet<CertificateContentFlags> contentFlags = EnumSet.noneOf(CertificateContentFlags.class);
		for( CertificateContentFlags flag : CertificateContentFlags.values())
			if ( (flag.getValue() & subjectTypeFlagsValue) != 0 )
				contentFlags.add(flag);
		return contentFlags;
	}
	
	public static boolean anyOf(EnumSet<CertificateContentFlags> enumSet, CertificateContentFlags ... flags) {
		for( CertificateContentFlags flag : flags )
			if ( enumSet.contains(flag) )
				return true;
		return false;
	}

}