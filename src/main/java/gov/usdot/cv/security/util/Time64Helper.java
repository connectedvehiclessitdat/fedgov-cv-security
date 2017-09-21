package gov.usdot.cv.security.util;

import java.util.Calendar;
import java.util.Date;

/**
 * 6.2.11 Time64 helper
 * Time64 is unsigned 64-bit integer giving the number of microseconds since 00:00:00 UTC, 1 January, 2004.
 */
public class Time64Helper {
	
	static final long time64ValueAdjustment;
	
	static {
		Calendar calendar = Calendar.getInstance();
		calendar.set(2004, Calendar.JANUARY, 1, 0, 0, 0);
		time64ValueAdjustment = calendar.getTime().getTime();
	}
	
	/**
	 * Converts 1609.2 Time64 value to java.util.Date.
	 * Note that this conversion will result in loss of microseconds present in time64 value
	 * @param time64 value to convert to Date
	 * @return converted java.util.Date value
	 */
	public static Date time64ToDate(long time64) {
		assert(time64 >= 0);
		return new Date(time64 / 1000 + time64ValueAdjustment);
	}
	
	/**
	 * Converts java.util.Date to Time64 time in microseconds
	 * @param date java.util.Date to convert
	 * @return number of microseconds since 00:00:00 UTC, 1 January, 2004.
	 */
	public static long dateToTime64(Date date) {
		return 1000 * (date.getTime() - time64ValueAdjustment);
	}

}
