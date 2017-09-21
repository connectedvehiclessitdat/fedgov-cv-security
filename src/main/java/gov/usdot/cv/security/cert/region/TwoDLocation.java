package gov.usdot.cv.security.cert.region;

import java.nio.ByteBuffer;

/**
 * 6.3.18 TwoDLocation encoder/decoder
 */
public class TwoDLocation {

	public final int latitude;
    public final int longitude;

    public TwoDLocation(int latitude, int longitude) {
    	this.latitude = latitude;
    	this.longitude = longitude;
    }

    public static TwoDLocation decode(ByteBuffer byteBuffer) {
        int latitude = byteBuffer.getInt();
        int longitude = byteBuffer.getInt();
        return new TwoDLocation(latitude, longitude);
    }
    
    public void encode(ByteBuffer byteBuffer) {
    	byteBuffer.putInt(latitude);
    	byteBuffer.putInt(longitude);
    }
    
    public static int getLength() {
    	return 4;
    }
    
    @Override
    public String toString() {
    	return String.format("%08x%08x", latitude, longitude);
    }
}
