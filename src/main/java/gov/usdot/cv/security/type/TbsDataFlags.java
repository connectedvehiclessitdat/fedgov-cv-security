package gov.usdot.cv.security.type;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

/**
 * 6.2.9 TbsDataFlags
 */
public enum TbsDataFlags {
	fragment 			(1<<0),
	useGenerationTime	(1<<1),
	expires 			(1<<2),
	useLocation 		(1<<3),
	extensions 			(1<<4);
	
	private final int tbsDataFlags;

	private static Map<Integer, TbsDataFlags> map = new HashMap<Integer, TbsDataFlags>();
	
	static {
		for( TbsDataFlags value : TbsDataFlags.values() )
			map.put(value.tbsDataFlags, value);
	}

	private TbsDataFlags(int tbsDataFlags) {
		this.tbsDataFlags = tbsDataFlags;
	}
	
	public int getValue() {
		return tbsDataFlags;
	}
	
	public static TbsDataFlags valueOf(int value ) {
		return map.get(value);
	}
	
	public static EnumSet<TbsDataFlags> create(int subjectTypeFlagsValue) {
		EnumSet<TbsDataFlags> tbsDataFlags = EnumSet.noneOf(TbsDataFlags.class);
		for( TbsDataFlags flag : TbsDataFlags.values())
			if ( (flag.getValue() & subjectTypeFlagsValue) != 0 )
				tbsDataFlags.add(flag);
		return tbsDataFlags;
	}
	
	public static boolean anyOf(EnumSet<TbsDataFlags> enumSet, TbsDataFlags ... flags) {
		for( TbsDataFlags flag : flags )
			if ( enumSet.contains(flag) )
				return true;
		return false;
	}

}