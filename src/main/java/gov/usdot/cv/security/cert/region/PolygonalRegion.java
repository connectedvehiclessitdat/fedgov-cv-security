package gov.usdot.cv.security.cert.region;

import java.nio.ByteBuffer;

import gov.usdot.cv.security.util.vector.VariableLengthVectorWithVariableLengthLength;
import gov.usdot.cv.security.util.vector.VectorException;

/**
 * 6.3.17 PolygonalRegion encoder/decoder
 */
class PolygonalRegion extends VariableLengthVectorWithVariableLengthLength<PolygonalRegionItem> {
	private static final long serialVersionUID = 1L;
	
	public static PolygonalRegion decode(ByteBuffer byteBuffer) throws VectorException {
		PolygonalRegion polygonalRegion = new PolygonalRegion();
		polygonalRegion.decode(byteBuffer, new PolygonalRegionItem(null));
		return polygonalRegion;
	}
	
    @Override
    public String toString() {
    	StringBuilder sb = new StringBuilder(String.format("%02x", size()));
    	for(PolygonalRegionItem item : this)
    		sb.append(item.getItem());
    	return sb.toString();
    }
}
