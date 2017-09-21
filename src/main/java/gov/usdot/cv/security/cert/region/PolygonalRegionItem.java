package gov.usdot.cv.security.cert.region;

import gov.usdot.cv.security.util.vector.EncodableVectorItem;
import gov.usdot.cv.security.util.vector.VectorException;

import java.nio.ByteBuffer;

/**
 * Vector element type for PolygonalRegion vector
 */
public class PolygonalRegionItem implements EncodableVectorItem<PolygonalRegionItem> {
	
	TwoDLocation item;
	
	public PolygonalRegionItem(TwoDLocation item) {
		this.item = item;
	}
	
	public TwoDLocation getItem() {
		return item;
	}

	@Override
	public int getLength() {
		return TwoDLocation.getLength();
	}

	@Override
	public void encode(ByteBuffer byteBuffer) throws VectorException {
		item.encode(byteBuffer);
	}

	@Override
	public PolygonalRegionItem decode(ByteBuffer byteBuffer) throws VectorException {
		item = TwoDLocation.decode(byteBuffer);
		return new PolygonalRegionItem(item);
	}

}


