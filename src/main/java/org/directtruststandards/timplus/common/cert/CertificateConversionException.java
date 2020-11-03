package org.directtruststandards.timplus.common.cert;

/**
 * Exception thrown when converting a certificate from one representation to another.  Examples are bytes streams to certificates or PKCS12 containers.
 * @author Greg Meyer
 *
 * @since 1.0
 */
public class CertificateConversionException extends RuntimeException 
{
	/**
	 * 
	 */
	private static final long serialVersionUID = -160957431943861209L;

	/**
	 * Empty constructor
	 */
    public CertificateConversionException() 
    {
    }

    /**
     * {@inheritDoc}
     */
    public CertificateConversionException(String msg) 
    {
        super(msg);
    }

    /**
     * {@inheritDoc}
     */
    public CertificateConversionException(String msg, Throwable t) 
    {
        super(msg, t);
    }

    /**
     * {@inheritDoc}
     */
    public CertificateConversionException(Throwable t) 
    {
        super(t);
    }
}
