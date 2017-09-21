package gov.usdot.cv.security.util;

import java.nio.ByteBuffer;

import org.apache.log4j.Logger;

/**
 * 
	<p>Provider Service Identifier as defined in IEEE 1609.3. 
	<p>This is a variable-length type that encodes the length inside the data rather than in an external length field. 
	<br>ProviderServiceIdentifier Octet string See 8.1.3 Identifies the PSID of the desired service.
	See "IEEE Std 1609.3-2010.pdf" page 53.
	<br>Decoding rules:
	<br>	if b7 of byte 0 is 0   - length is 1 byte and remaining bits are value
	<br>	if b7 is 1
	<br>		if b6 is 0   	   - length is 2 bytes and remaining bits are value - subtract 8000H to get value
	<br>		if b6 is 1
	<br>		   if b5 is 0 	   - length is 3 bytes and remaining bits are value - subtract c00000H to get value
	<br>		   if b5 is 1
	<br>			if b4 is 0 	   - length is 4 bytes and remaining bits are value - subtract E0000000H to get value
	<p>	In other words - position (index+1) from the left of the first 0 bit defines length
	<br>0 - 7F 		 		-&gt; encode in one byte
	<br>80 - 3FFF 	 		-&gt; encode in two bytes and add 8000
	<br>4000 - 1FFFFF 	 	-&gt; encode in 3 bytes add C00000
	<br>200000 - FFFFFFF 	-&gt; encode in 4 bytes add E0000000
 *
 */
public class PSIDHelper {
	
	public static final int maxPSIDValue = 0xFFFFFFF;
	
	private static final Logger log = Logger.getLogger(PSIDHelper.class);

	/**
	 * Calculates number of bytes that need to be used to encode this PSID
	 * @param psid the psid
	 * @return Positive number of bytes that will be used to encode this PSID or -1 if PSID value is invalid
	 */
	static public int calculateLength(int psid)  {
		if ( psid >= 0 && psid <= 0x7F )
			return 1;
		if ( psid >= 0x80 && psid <= 0x3FFF )
			return 2;
		if ( psid >= 0x4000 && psid <= 0x1FFFFF )
			return 3;
		if ( psid >= 0x200000 && psid <= 0xFFFFFFF )
			return 4;
		log.error(String.format("Couldn't detect encoded length for PSID value 0x%x (%d)", psid, psid));
		return -1;
	}
	
	/**
	 * Encodes PSID value
	 * @param messageBuffer ByteBuffer to encode into
	 * @param psid PSID value to encode
	 * @return true if PSID was successfully encoded and false otherwise
	 */
	static public boolean encodePSID(ByteBuffer messageBuffer, int psid) {
		int encodedPSID = 0;
		int size = 0;
		if ( psid >= 0 && psid <= 0x7F ) {
			encodedPSID = psid;
			size = 1;
		} else if ( psid >= 0x80 && psid <= 0x3FFF ) {
			encodedPSID = psid + 0x8000;
			size = 2;
		} else if ( psid >= 0x4000 && psid <= 0x1FFFFF ) {
			encodedPSID = psid + 0xC00000;
			size = 3;
		} else if ( psid >= 0x200000 && psid <= 0xFFFFFFF ) {
			encodedPSID = psid + 0xE0000000;
			size = 4;
		} else {
			log.error(String.format("Couldn't encode PSID value 0x%x", psid));
			return false;
		}
		byte[] bytes = new byte[size];
		for (int i = size - 1; i >= 0; i--) {
			bytes[i] = (byte) (encodedPSID & 0xFF);
			encodedPSID >>>= 8;
        }
		messageBuffer.put(bytes);
		return true;
	}
	
	/**
	 * Decode PSID value
	 * @param messageBuffer ByteBuffer to decode from
	 * @return decoded PSID value or -1 if decoding failed
	 */
	static public int decodePSID(ByteBuffer messageBuffer) {
		int highByte = (messageBuffer.get() & 0xFF);
		int mask = 0x80;
		int size = 1;
		while( (highByte & mask) > 0 && size < 5 ) {
			size++;
			mask >>>= 1;
		}
		int psid = highByte;
		for( int i = size-1; i > 0; i-- ) {
			psid <<= 8;
			psid += (messageBuffer.get() & 0xFF);
		}
		switch(size) {
		case 1: return psid;
		case 2: return psid - 0x8000;
		case 3: return psid - 0xC00000;
		case 4: return psid - 0xE0000000;
		default: 
			log.error(String.format("Couldn't decode PSID value from message buffer. High byte: 0x%x. Size: ", highByte, size, psid));
			return -1;
		}
	}

}
