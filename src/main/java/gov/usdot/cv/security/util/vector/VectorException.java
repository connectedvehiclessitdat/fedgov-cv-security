package gov.usdot.cv.security.util.vector;

/**
 * 1609.2 vector exception
 */
public class VectorException extends Exception {

	private static final long serialVersionUID = 1L;

	public VectorException(String message) {
		super(message);
	}

	public VectorException(Throwable cause) {
		super(cause);
	}

	public VectorException(String message, Throwable cause) {
		super(message, cause);
	}

}
