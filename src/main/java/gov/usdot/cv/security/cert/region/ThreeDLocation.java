package gov.usdot.cv.security.cert.region;

import java.nio.ByteBuffer;

/**
 * 6.2.12 ThreeDLocation encoder/decoder
 */
public class ThreeDLocation {

	public final int latitude;
    public final int longitude;
    public final short elevation;

    public ThreeDLocation(int latitude, int longitude, short elevation) {
    	this.latitude = latitude;
    	this.longitude = longitude;
    	this.elevation = elevation;
    }

    public static ThreeDLocation decode(ByteBuffer byteBuffer) {
        int latitude = byteBuffer.getInt();
        int longitude = byteBuffer.getInt();
        short elevation = byteBuffer.getShort();
        return new ThreeDLocation(latitude, longitude, elevation);
    }
    
    public void encode(ByteBuffer byteBuffer) {
    	byteBuffer.putInt(latitude);
    	byteBuffer.putInt(longitude);
    	byteBuffer.putShort(elevation);
    }
    
    public static int getLength() {
    	return 6;
    }
    
    @Override
    public String toString() {
    	return String.format("%08x%08x%04x", latitude, longitude, elevation);
    }
}
