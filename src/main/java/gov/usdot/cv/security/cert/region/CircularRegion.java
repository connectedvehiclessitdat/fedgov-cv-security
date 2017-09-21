package gov.usdot.cv.security.cert.region;

import java.nio.ByteBuffer;

/**
 * 6.3.15 CircularRegion encoder/decoder
 */
public class CircularRegion {

    public final TwoDLocation center;
    public final short radius;

    public CircularRegion(TwoDLocation center, short radius) {
    	this.center = center;
    	this.radius = radius;
    }

    public static CircularRegion decode(ByteBuffer byteBuffer) {
    	TwoDLocation center = TwoDLocation.decode(byteBuffer);
    	short radius = byteBuffer.getShort();
    	return new CircularRegion(center, radius);
    }

    public void encode(ByteBuffer byteBuffer) {
    	center.encode(byteBuffer);
    	byteBuffer.putShort(radius);
    }
    
    @Override
    public String toString() {
    	return String.format("%s%04x", center, radius);
    }
}

