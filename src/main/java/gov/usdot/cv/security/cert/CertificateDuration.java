package gov.usdot.cv.security.cert;

import java.nio.ByteBuffer;

import org.apache.log4j.Logger;

/**
 * CertificateDuration (6.3.5)<br>
 * Certificate Duration values are encoded as a 2-byte unsigned integer
 * with the top 3 bits indicating the units and the bottom 13 bits 
 * indicating the value in those units. The available units are seconds (000),
 * minutes (001), hours (010), 60-hour blocks (011), and years (100).
 *
 */
public class CertificateDuration {
	
	private static final Logger log = Logger.getLogger(CertificateDuration.class);
	
	static private final int maxValue = (1<<13) - 1;
	static private final int secInMin 	= 60;			// minutes (= 60 seconds)
	static private final int secInHour 	= 3600;			// hours (= 3600 seconds)
	static private final int secInBlock 	= 60*secInHour;	// 60-hour blocks (= 3600 minutes)
	static private final int secInYear 	= 31556925;		// year (=31556925 seconds)

	/**
	 * Certificate duration units bits<br>
	 * 0 is seconds; 1 is minutes; 2 is hours; 3 is 60-hour blocks; 4 is years; 5, 6, 7 are undefined
	 */
	private byte units;
	
	/**
	 * Certificate duration value in units; min value 0, max value 8191
	 */
	private short value;
	
	/**
	 * Instantiates certificate duration from seconds
	 * @param seconds number of seconds
	 */
	public CertificateDuration(long seconds) {
		put(seconds);
	}
	
	/**
	 * Instantiates certificate from units and value in units
	 * @param units units bits value (0-4)
	 * @param value units specific value (0-8191)
	 */
	public CertificateDuration(byte units, short value) {
		assert( units >= 0 && units <= 4);
		assert( value >= 0 && value <= maxValue);
		this.units = units;
		this.value = value;
	}
	
	/**
	 * Creates certificate duration instance from bytes
	 * @param byteBuffer buffer containing the certificate duration
	 * @return certificate duration instance
	 */
	static public CertificateDuration decode(ByteBuffer byteBuffer) {
		int duration = byteBuffer.getShort() & 0xFFFF;
		int value = duration & 0x1FFF;
		int units = duration >>> 13;
		return new CertificateDuration((byte)units, (short)value);
	}
	
	/**
	 * Encodes a certificate duration into a buffer
	 * @param byteBuffer buffer to encode into
	 */
	public void encode(ByteBuffer byteBuffer) {
		byteBuffer.putShort((short)((units << 13) | (value & 0x1FFF) ));
	}
	
	/**
	 * Retrieves certificate duration units bits
	 * @return certificate duration units bits value
	 */
	public byte getUnits() {
		return units;
	}

	/**
	 * Retrieves certificate duration value in units
	 * @return certificate duration value in units
	 */
	public int getValue() {
		return value;
	}
	
	/**
	 * Gets duration in seconds
	 * @return duration in seconds
	 */
	public long get() {
		switch( (int)units ) {
		default: 								// fall through to set value is seconds
			log.warn("Unexpected units value: " + units);
		case 0: return value;					// seconds
		case 1: return value*secInMin;			// minutes (= 60 seconds)
		case 2: return value*secInHour;			// hours (= 3600 seconds)
		case 3: return value*secInBlock;		// 60-hour blocks (= 3600 minutes)
		case 4: return value*(long)secInYear;	// year (=31556925 seconds)
		}
	}

	/**
	 * Sets appropriate units and value from seconds
	 * @param seconds number of seconds
	 */
	public void put(long seconds) {
		if (seconds <= maxValue) {
			units = 0;
			value = (short)seconds;
		} else if (seconds <= maxValue*secInMin) {
			units = 1;
			value = (short)(seconds/secInMin);
		} else if (seconds <= maxValue*secInHour) {
			units = 2;
			value = (short)(seconds/secInHour);
		} else if (seconds <= (long)maxValue*secInBlock) {
			units = 3;
			value = (short)(seconds/secInBlock);
		} else if (seconds <= (long)maxValue*secInYear) {
			units = 4;
			value = (short)(seconds/secInYear);
		} else {
			units = 4;
			value = maxValue;
			log.warn(String.format("Truncated seconds value; original value: %14d, truncated value: %d years (%d seconds)", seconds, value, value*secInYear));
		}
	}
}
