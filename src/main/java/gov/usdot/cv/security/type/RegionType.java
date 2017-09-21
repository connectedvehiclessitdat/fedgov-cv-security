package gov.usdot.cv.security.type;

import java.util.HashMap;
import java.util.Map;

/**
 * 6.3.10 RegionType
 */
public enum RegionType {
    FromIssuer(0),
    Circle(1),
    Rectangle(2),
    Polygon(3),
    None(4),
    Unknown(1<<8-1);

    private final int regionType;

    private static Map<Integer, RegionType> map = new HashMap<Integer, RegionType>();

    static {
        for (RegionType value : RegionType.values())
            map.put(value.regionType, value);
    }

    private RegionType(int contentType) {
        this.regionType = contentType;
    }

    public int getValue() {
        return regionType;
    }

    public static RegionType valueOf(int value) {
        return map.get(value);
    }
}
