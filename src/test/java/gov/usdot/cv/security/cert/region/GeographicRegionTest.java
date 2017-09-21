package gov.usdot.cv.security.cert.region;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNull;

import java.nio.ByteBuffer;
import java.util.Arrays;

import gov.usdot.cv.security.cert.CertificateException;
import gov.usdot.cv.security.type.RegionType;
import gov.usdot.cv.security.util.ByteBufferHelper;
import gov.usdot.cv.security.util.UnitTestHelper;
import gov.usdot.cv.security.util.vector.VectorException;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;

public class GeographicRegionTest {
	
	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(GeographicRegionTest.class);

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        UnitTestHelper.initLog4j(isDebugOutput);
    }
    
    @Test
    public void testCircularRegion() throws VectorException, CertificateException {
    	TwoDLocation center = new TwoDLocation(0x1234, 0x5678);
    	short radius = 0x910;
    	CircularRegion circularRegion = new CircularRegion(center, radius);
    	log.debug("CircularRegion:     " + circularRegion);
    	ByteBuffer byteBuffer = ByteBuffer.allocate(1024);
    	circularRegion.encode(byteBuffer); 
    	assertTrue(Hex.toHexString(ByteBufferHelper.copyBytes(byteBuffer)).equals(circularRegion.toString()));
    	byteBuffer.rewind();
    	CircularRegion circularRegion2 = CircularRegion.decode(byteBuffer);
    	assertEquals(circularRegion.toString(), circularRegion2.toString());
    	
    	GeographicRegion region = new GeographicRegion(RegionType.Circle, circularRegion);
    	byteBuffer.clear();
    	region.encode(byteBuffer);
    	byte[] regionBytes = ByteBufferHelper.copyBytes(byteBuffer);
    	log.debug("GeographicRegion: " + Hex.toHexString(regionBytes));
    	byteBuffer.rewind();
    	GeographicRegion region2 = GeographicRegion.decode(byteBuffer);
    	assertEquals(region.regionType.getValue(),region2.regionType.getValue());
    	assertEquals(region.region.toString(),region2.region.toString());
    }
    
    @Test
    public void testRectangularRegion() throws VectorException, CertificateException {
        TwoDLocation upperLeft  = new TwoDLocation(0x1234, 0x5678);
        TwoDLocation lowerRight = new TwoDLocation(0x9abc, 0xef01);
        RectangularRegion rectangularRegion = new RectangularRegion(upperLeft, lowerRight);
       	log.debug("RectangularRegion:  " + rectangularRegion);
    	ByteBuffer byteBuffer = ByteBuffer.allocate(1024);
    	rectangularRegion.encode(byteBuffer); 
    	assertTrue(Hex.toHexString(ByteBufferHelper.copyBytes(byteBuffer)).equals(rectangularRegion.toString()));
    	byteBuffer.rewind();
    	RectangularRegion rectangularRegion2 = RectangularRegion.decode(byteBuffer);
    	assertEquals(rectangularRegion.toString(), rectangularRegion2.toString());
    	
    	GeographicRegion region = new GeographicRegion(RegionType.Rectangle, rectangularRegion);
    	byteBuffer.clear();
    	region.encode(byteBuffer);
    	byte[] regionBytes = ByteBufferHelper.copyBytes(byteBuffer);
    	log.debug("GeographicRegion: " + Hex.toHexString(regionBytes));
    	byteBuffer.rewind();
    	GeographicRegion region2 = GeographicRegion.decode(byteBuffer);
    	assertEquals(region.regionType.getValue(),region2.regionType.getValue());
    	assertEquals(region.region.toString(),region2.region.toString());
    }

    @Test
    public void testPolygonalRegion() throws VectorException, CertificateException  {
        TwoDLocation point1 = new TwoDLocation(0x1234, 0x5678);
        TwoDLocation point2 = new TwoDLocation(0xdead, 0xbeef);
        TwoDLocation point3 = new TwoDLocation(0xcafe, 0xbabe);
        PolygonalRegion polygonalRegion = new PolygonalRegion();
        polygonalRegion.add(new PolygonalRegionItem(point1));
        polygonalRegion.add(new PolygonalRegionItem(point2));
        polygonalRegion.add(new PolygonalRegionItem(point3));
       	log.debug("PolygonalRegion:    " + polygonalRegion);

    	ByteBuffer byteBuffer = ByteBuffer.allocate(1024);
    	polygonalRegion.encode(byteBuffer); 
       	log.debug("PolygonalRegion Enc:" + Hex.toHexString(ByteBufferHelper.copyBytes(byteBuffer)));
    	byteBuffer.rewind();
    	PolygonalRegion polygonalRegion2 = PolygonalRegion.decode(byteBuffer);
    	assertEquals(polygonalRegion.toString(), polygonalRegion2.toString());

    	GeographicRegion region = new GeographicRegion(RegionType.Polygon, polygonalRegion);
    	byteBuffer.clear();
    	region.encode(byteBuffer);
    	byte[] regionBytes = ByteBufferHelper.copyBytes(byteBuffer);
    	log.debug("GeographicRegion: " + Hex.toHexString(regionBytes));
    	byteBuffer.rewind();
    	GeographicRegion region2 = GeographicRegion.decode(byteBuffer);
    	assertEquals(region.regionType.getValue(),region2.regionType.getValue());
    	assertEquals(region.region.toString(),region2.region.toString());

    }
    
    @Test
    public void testOtherRegion() throws VectorException, CertificateException  {
    	final String text = "Hello, World!";
    	byte[] other = text.getBytes();
    	GeographicRegion region = new GeographicRegion(RegionType.Unknown, other);
    	ByteBuffer byteBuffer = ByteBuffer.allocate(1024);
    	region.encode(byteBuffer);
    	byte[] regionBytes = ByteBufferHelper.copyBytes(byteBuffer);
    	log.debug("GeographicRegion: " + Hex.toHexString(regionBytes));
    	byteBuffer.rewind();
    	GeographicRegion region2 = GeographicRegion.decode(byteBuffer);
    	assertEquals(region.regionType.getValue(),region2.regionType.getValue());
    	assertTrue(Arrays.equals((byte[])region.region,(byte[])region2.region));
    	assertEquals(text, new String((byte[])region2.region));
    }
    
    @Test
    public void testNoneRegion() throws VectorException, CertificateException {
    	testEmptyRegion(RegionType.None);
    	testEmptyRegion(RegionType.FromIssuer);
    }
    
    private void testEmptyRegion(RegionType type) throws VectorException, CertificateException {
    	GeographicRegion region = new GeographicRegion(type, null);
    	ByteBuffer byteBuffer = ByteBuffer.allocate(1024);
    	region.encode(byteBuffer);
    	byte[] regionBytes = ByteBufferHelper.copyBytes(byteBuffer);
    	log.debug("GeographicRegion: " + Hex.toHexString(regionBytes));
    	byteBuffer.rewind();
    	GeographicRegion region2 = GeographicRegion.decode(byteBuffer);
    	assertEquals(region.regionType.getValue(),region2.regionType.getValue());
    	assertNull(region.region);
    	assertNull(region2.region);
    }
    
}
