package gov.usdot.cv.security.cert.region;

import gov.usdot.cv.security.type.RegionType;
import gov.usdot.cv.security.cert.CertificateException;
import gov.usdot.cv.security.cert.region.CircularRegion;
import gov.usdot.cv.security.cert.region.RectangularRegion;
import gov.usdot.cv.security.util.vector.OpaqueVariableLengthVector;
import gov.usdot.cv.security.util.vector.VectorException;

import java.nio.ByteBuffer;

/**
 * 6.3.13 GeographicRegion encoder/decoder
 */
public class GeographicRegion {
   
    public final RegionType regionType;
    public final Object region;
    
    public GeographicRegion(RegionType regionType, Object region) {
    	this.regionType = regionType;
    	this.region = region;
    }
    
    public void encode(ByteBuffer byteBuffer) throws VectorException {
    	byteBuffer.put((byte)regionType.getValue());
        switch (regionType) {
        case FromIssuer:
        case None:
            break;
        case Circle:
        	CircularRegion circularRegion = (CircularRegion)region;
        	circularRegion.encode(byteBuffer);
            break;
        case Rectangle:
            RectangularRegion rectangularRegion = (RectangularRegion)region;
            rectangularRegion.encode(byteBuffer);
            break;
        case Polygon:
            PolygonalRegion polygonRegion = (PolygonalRegion)region;
            polygonRegion.encode(byteBuffer);
            break;
        case Unknown:
        default:
        	OpaqueVariableLengthVector.encode(byteBuffer, (byte[])region);
            break;
        }
    }
    
    public static GeographicRegion decode(ByteBuffer byteBuffer) throws CertificateException, VectorException {
        int regionTypeValue = byteBuffer.get() & 0xFF;
        RegionType regionType = RegionType.valueOf(regionTypeValue);
        if ( regionType == null )
        	throw new CertificateException(String.format("Unsupported geographic region type %d", regionTypeValue));
        Object region = null;
        switch (regionType) {
        case FromIssuer:
        case None:
            break;
        case Circle:
        	region = CircularRegion.decode(byteBuffer);
            break;
        case Rectangle:
        	region = RectangularRegion.decode(byteBuffer);
            break;
        case Polygon:
        	region = PolygonalRegion.decode(byteBuffer);
            break;
        case Unknown:
        default:
        	region = OpaqueVariableLengthVector.decode(byteBuffer);
            break;
        }
        return new GeographicRegion(regionType, region);
    }
    
}