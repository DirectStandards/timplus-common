package org.directtruststandards.timplus.common.cert;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;

import org.apache.commons.lang3.StringUtils;
import org.directtruststandards.timplus.common.crypto.KeyStoreProtectionManager;
import org.directtruststandards.timplus.common.crypto.MutableKeyStoreProtectionManager;
import org.directtruststandards.timplus.common.crypto.exceptions.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility methods for working with certificate data stores and proprietary certificate data formats.  These operations generally
 * use a key store protection manager when available.  
 * @author Greg Meyer
 *
 * @since 1.0
 */
public class CertStoreUtils
{
	private final static byte[] KEY_PAIR_START_STRING;
	
	static
	{
		KEY_PAIR_START_STRING = getSafeChars();
	}	
	
	static private byte[] getSafeChars()
	{
		byte[] retVal = null;
		try
		{
			retVal = "STARTCERTPRIVKEYPAIR".getBytes("ASCII");
		}
		catch (Exception e){/* no-op */}
		return retVal;
	}	
	
	private static final Logger LOGGER = LoggerFactory.getLogger(CertStoreUtils.class);
	
	/**
	 * Converts a byte array that has been retrieved from a certificate store into an appropriate X509Certificate representation.  
	 * The data store maintains different storage formats based on the availability of a key store manager.  The certificate object returned
	 * hides details of the underlying key store format and private storage.
	 * @param mgr The key store manager.
	 * @param data Byte array of the raw certificate storage format from the certificate data store.
	 * @return An X509Certificate object transformed from raw data storage format.
	 * @throws CryptoException Thrown if the raw data cannot be converted into a usable X509Certificate 
	 */
    public static X509Certificate certFromData(KeyStoreProtectionManager mgr,  byte[] data) throws CryptoException
    {
    	X509Certificate retVal = null;
        try 
        {
        	// first check for wrapped data
        	final CertContainer container = CertStoreUtils.toCertContainer(data);
        	if (container.getWrappedKeyData() != null)
        	{
        		// this is a wrapped key
        		// make sure we have a KeyStoreManager configured
        		if (mgr == null)
        		{
        			throw new CryptoException("Resolved certifiate has wrapped data, but resolver has not been configured to unwrap it.");
        		}
        		
        		// create a new wrapped certificate object
        		retVal = WrappedOnDemandX509CertificateEx.fromX509Certificate(mgr, container.getCert(), container.getWrappedKeyData());
        		return retVal;
        	}
        	
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            
            // lets try this a as a PKCS12 data stream first
            try
            {
            	KeyStore localKeyStore = KeyStore.getInstance("PKCS12", "BC");
            	
            	localKeyStore.load(bais, "".toCharArray());
            	Enumeration<String> aliases = localKeyStore.aliases();


        		// we are really expecting only one alias 
        		if (aliases.hasMoreElements())        			
        		{
        			String alias = aliases.nextElement();
        			X509Certificate cert = (X509Certificate)localKeyStore.getCertificate(alias);
        			
    				// check if there is private key
    				Key key = localKeyStore.getKey(alias, "".toCharArray());
    				if (key != null && key instanceof PrivateKey) 
    				{
    					retVal = X509CertificateEx.fromX509Certificate(cert, (PrivateKey)key);
    				}
    				else
    					retVal = cert;
    					
        		}
            }
            catch (Exception e)
            {
            	// must not be a PKCS12 stream, go on to next step
            }
   
            if (retVal == null)            	
            {
            	//try X509 certificate factory next       
                bais.reset();
                bais = new ByteArrayInputStream(data);

                retVal = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(bais);            	
            }
            bais.close();
            
            // if this is a certificate an no private key, and the keystore manager is configured,
            // look in the keystore manager to check if they private key is store in the token
            if (mgr != null && !(retVal instanceof X509CertificateEx))
            {
            	// make sure this a mutable manager
            	if (mgr instanceof MutableKeyStoreProtectionManager)
            	{
            		try
            		{
	            		final KeyStore ks = ((MutableKeyStoreProtectionManager)mgr).getKS();
	            		// check to see if this certificate exists in the key store
	            		final String alias = ks.getCertificateAlias(retVal);
	            		if (!StringUtils.isEmpty(alias))
	            		{
	            			// get the private key if it exits
	            			final PrivateKey pKey = (PrivateKey)ks.getKey(alias, "".toCharArray());
	            			if (pKey != null)
	            				retVal = X509CertificateEx.fromX509Certificate(retVal, pKey);
	            		}
            		}
            		catch (Exception e)
            		{
            			LOGGER.warn("Could not retrieve the private key from the PKCS11 token: " + e.getMessage(), e);
            		}
            	}
            }
            
        } 
        catch (Exception e) 
        {
            throw new CryptoException("Data cannot be converted to a valid X.509 Certificate", e);
        }
        
        return retVal;
    }
    
    /**
     * Determines is the raw certificate data store format contains wrapped private key data.
     * @param data The certificate data store representation.
     * @return True if the data store representation contains wrapped private key data.  False otherwise.
     */
    protected static boolean isByteDataWrappedKeyPair(byte[] data)
    {
    	if (data.length <= KEY_PAIR_START_STRING.length)
    		return false;
    	
    	// compare first KEY_PAIR_START_STRING.length bytes
    	for (int idx = 0; idx < KEY_PAIR_START_STRING.length; ++idx)
    		if (data[idx] != KEY_PAIR_START_STRING[idx])
    			return false;
    	
    	return true;
    }    
    
    /**
     * Converts a raw certificate data store representation into a CertContainer.
     * @param data The certificate data store representation.
     * @return A CertContainer object that contains the decoded X509 certificate 
     * @throws CertificateConversionException Thrown is the certificate cannot be converted into a CertContainer.
     */
    public static CertContainer toCertContainer(byte[] data) throws CertificateConversionException 
    {
    	return toCertContainer(data, "".toCharArray(), "".toCharArray());
    }
    
    /**
     * Converts a raw certificate data store representation into a CertContainer.  The raw representation may be an encrypted PCKS12 format in which
     * case pass phrases are required to decrypt the data.
     * @param data The certificate data store representation.
     * @param keyStorePassPhrase The keystore password.
     * @param privateKeyPassPhrase The private key password.
     * @return  A CertContainer object that contains the decoded X509 certificate 
     * @throws CertificateConversionException Thrown is the certificate cannot be converted into a CertContainer.
     */
	public static CertContainer toCertContainer(byte[] data, char[] keyStorePassPhrase, char[] privateKeyPassPhrase) throws CertificateConversionException 
    {
    	CertContainer certContainer = null;
        try 
        {
        	// first check if the byte array starts with the magic string
        	if (isByteDataWrappedKeyPair(data))
        	{
        		int idx = KEY_PAIR_START_STRING.length;
        		// the next 2 bytes are the size of the certificate data
        		// convert it to an int
        		// need to take into consideration that bytes in Java are signed and be aware of compliment representations
        		int high = (data[idx] >= 0) ? data[idx] : (data[idx] + 256);
        		++idx;
        		int low = (data[idx] >= 0) ? data[idx] : (data[idx] + 256);
        		int wrappedDatasize = low | (high << 8);
        		++idx;
        		
        		final byte[] wrappedData = Arrays.copyOfRange(data, idx, idx + wrappedDatasize);
        		idx += wrappedDatasize;
        		
        		try (final ByteArrayInputStream bais = new ByteArrayInputStream(Arrays.copyOfRange(data, idx, data.length)))
        		{
        			return new CertContainer((X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(bais), wrappedData);
        		}
 
        	}
        	
        	// magic string doesn't exist.. let's try some other methods
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            
            // lets try this a as a PKCS12 data stream first
            try
            {
            	KeyStore localKeyStore = KeyStore.getInstance("PKCS12", "BC");
            	
            	localKeyStore.load(bais, keyStorePassPhrase);
            	Enumeration<String> aliases = localKeyStore.aliases();


        		// we are really expecting only one alias 
        		if (aliases.hasMoreElements())        			
        		{
        			String alias = aliases.nextElement();
        			X509Certificate cert = (X509Certificate)localKeyStore.getCertificate(alias);
        			
    				// check if there is private key
    				Key key = localKeyStore.getKey(alias, privateKeyPassPhrase);
    				if (key != null && key instanceof PrivateKey) 
    				{
    					certContainer = new CertContainer(cert, key);
    					
    				}
        		}
            }
            catch (Exception e)
            {
            	// must not be a PKCS12 stream, go on to next step
            }
   
            if (certContainer == null)            	
            {
            	//try X509 certificate factory next       
                bais.reset();
                bais = new ByteArrayInputStream(data);

            	X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(bais);
            	certContainer = new CertContainer(cert, (Key)null);
            }
            bais.close();
        } 
        catch (Exception e) 
        {
            throw new CertificateConversionException("Data cannot be converted to a valid X.509 Certificate", e);
        }
        
        return certContainer;
    }    
    
	/**
	 * Converts a certificate and a wrapped private key into a certificate data store format representation.
	 * @param wrappedKey The wrapped private key.
	 * @param cert The X509Certificate
	 * @return A byte array that is a raw certificate data store format representation of the certificate and its wrapped private key.
	 * @throws CertificateConversionException Thrown if the private key and certificate cannot be converted.
	 */
	public static byte[] certAndWrappedKeyToRawByteFormat(byte[] wrappedKey, X509Certificate cert) throws CertificateConversionException 
    {
    	
    	
    	try (final ByteArrayOutputStream outStream = new ByteArrayOutputStream())
    	{
    		// write the magic string
    		outStream.write(KEY_PAIR_START_STRING);
    		// write the size of the the wrapped key
    		// size is going to be > 256, so need to split it into two bytes
    		int size = wrappedKey.length;
    		outStream.write((byte) ((size >> 8) & 0xFF));
    		outStream.write((byte) (size & 0xFF));
    		// write the wrapped key data
    		outStream.write(wrappedKey);
    		// write the encoded certificate
    		outStream.write(cert.getEncoded());
    		
    		return outStream.toByteArray();
    	}
    	catch (Exception e)
    	{
    		throw new CertificateConversionException("Failed to convert wrapped key and cert to byte stream.", e);
    	}
    }
    
	/**
	 * Container object of a certificate and its private key.  Depending on the underlying certificate data store format, the private key may either
	 * be either be stored in the Key object or in the wrappedKeyData object.
	 * @author Greg Meyer
	 *
	 * @since 1.0
	 */
    public static class CertContainer
    {
		private final X509Certificate cert;
    	private final Key key;
    	private final byte[] wrappedKeyData;
    	
    	public CertContainer(X509Certificate cert, Key key)
    	{
    		this.cert = cert;
    		this.key = key;
    		this.wrappedKeyData = null;
    	}
    	
    	public CertContainer(X509Certificate cert, byte[] wrappedKeyData)
    	{
    		this.cert = cert;
    		this.key = null;
    		this.wrappedKeyData = wrappedKeyData;
    	}
    	
    	public X509Certificate getCert() 
    	{
			return cert;
		}

		public Key getKey() 
		{
			return key;
		}
		
		public byte[] getWrappedKeyData()
		{
			return wrappedKeyData;
		}
    }  
    
}
