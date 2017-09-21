package gov.usdot.cv.security.util;

import java.util.Calendar;
import java.util.Date;

/**
 * 6.3.30 Time32 Helper
 * The Time32 type is a unsigned 32-bit integer giving the number of seconds since 00:00:00 UTC, 1 January, 2004. 
 */
public class Time32Helper {
	
	
	static final long time32ValueAdjustment;
	
	static {
		Calendar calendar = Calendar.getInstance();
		calendar.set(2004, Calendar.JANUARY, 1, 0, 0, 0);
		time32ValueAdjustment = calendar.getTime().getTime();
	}

	/**
	 * Converts Time32 to java.util.Date
	 * @param time32 as unsigned 32-bin integer
	 * @return time as java.util.Date
	 */
	public static Date time32ToDate(int time32) {
		long time = time32 & 0x00000000ffffffffL;
		return new Date(time*1000 + time32ValueAdjustment);
	}
	
	/**
	 * Converts java.util.Date to Time32 with rounding
	 * @param date java.util.Date to convert
	 * @return  number of seconds since 00:00:00 UTC, 1 January, 2004.
	 */
	public static int dateToTime32(Date date) {
		return (int)((date.getTime() - time32ValueAdjustment + 500)/1000);
	}
}
