package gov.usdot.cv.security.cert.region;

import java.nio.ByteBuffer;

/**
 * 6.3.16 RectangularRegion encoder/decoder
 */
public class RectangularRegion {

    public final TwoDLocation upperLeft;
    public final TwoDLocation lowerRight;

    public RectangularRegion(TwoDLocation upperLeft, TwoDLocation lowerRight) {
    	this.upperLeft = upperLeft;
    	this.lowerRight = lowerRight;
    }

    public static RectangularRegion decode(ByteBuffer byteBuffer) {
    	TwoDLocation upperLeft = TwoDLocation.decode(byteBuffer);
    	TwoDLocation lowerRight = TwoDLocation.decode(byteBuffer);
    	return new RectangularRegion(upperLeft, lowerRight);
    }
    
    public void encode(ByteBuffer byteBuffer) {
    	upperLeft.encode(byteBuffer);
    	lowerRight.encode(byteBuffer);
    }
    
    @Override
    public String toString() {
    	return String.format("%s%s", upperLeft, lowerRight);
    }

}

