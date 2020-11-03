package org.directtruststandards.timplus.common.cert;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.directtruststandards.timplus.common.crypto.KeyStoreProtectionManager;
import org.directtruststandards.timplus.common.crypto.WrappableKeyProtectionManager;
import org.directtruststandards.timplus.common.crypto.exceptions.CryptoException;

/**
 * Implementation of the X509CertificateEx class that utilized wrapped private keys and installs
 * them in the backing key store manager only when first needed.  In some cases, the wrapped private key data
 * is retrieved but never used wasting resources in unwrapping the keys.
 * <br>
 * Depending on the key manager that wrapped the keys, and specific JCE provider will most likely be needed
 * to utilize the private key.  For example, may PKCS11 tokens never expose the unwrapped private key data within
 * a JVM meaning that a JCE provider corresponding to the PKCS11 token would be needed.
 * @author Greg Meyer
 * 
 * @since 1.0
 */
public class WrappedOnDemandX509CertificateEx extends X509CertificateEx
{
	protected final KeyStoreProtectionManager mgr;
	protected final byte[] wrappedData;
	protected PrivateKey wrappedKey;
	
	/**
	 * Creates an instance by proviing the certificate, the wrapped private key, and KeyStoreProtectionManager that can unwrap the
	 * key.
	 * @param mgr The keystore protection manager used to unwrap the private key
	 * @param cert The certificate.
	 * @param wrappedData A wrapped representation of the private key
	 * @return An X509CertificateEx instance
	 */
	public static X509CertificateEx fromX509Certificate(KeyStoreProtectionManager mgr, X509Certificate cert, byte[] wrappedData)
	{
		if (cert == null || wrappedData == null || wrappedData.length == 0)
			throw new IllegalArgumentException("Cert or wrapped data cannot be null");
		
		if (mgr == null) 
			throw new IllegalArgumentException("KeyStore manager cannot be null");
		
		if (!(mgr instanceof WrappableKeyProtectionManager))
			throw new IllegalArgumentException("Key store must implement the WrappableKeyProtectionManager interface");
		
		return new WrappedOnDemandX509CertificateEx(mgr, cert, wrappedData);
	}
	
	/**
	 * Protected constructor
	 * @param mgr The keystore protection manager used to unwrap the private key
	 * @param cert The certificate.
	 * @param wrappedData A wrapped representation of the private key
	 */
	protected WrappedOnDemandX509CertificateEx(KeyStoreProtectionManager mgr, X509Certificate cert, byte[] wrappedData)
	{
		super(cert, null);
		
		this.mgr = mgr;
		this.wrappedData = wrappedData;
	}
	
    /**
     * {@inheritDoc}}
     */
	@Override
    public boolean hasPrivateKey()
    {
    	return wrappedData != null;
    }
    
    /**
     * {@inheritDoc}}
     */
    public synchronized PrivateKey getPrivateKey()
    {
    	// this is on demand, so it needs to be synchronized
    	
    	if (wrappedKey != null)
    		return wrappedKey;
    		
    	final WrappableKeyProtectionManager wrapManager = (WrappableKeyProtectionManager)mgr;
    	// get the key algorithm from the public key... this will be needed
    	// as a parameter to the unwrap method
    	final String keyAlg = this.internalCert.getPublicKey().getAlgorithm();
    	try
    	{
    		wrappedKey = (PrivateKey)wrapManager.unwrapWithSecretKey((SecretKey)mgr.getPrivateKeyProtectionKey(), wrappedData, keyAlg, Cipher.PRIVATE_KEY);
    	}
    	catch (CryptoException e)
    	{
    		throw new IllegalStateException("Failed to access wrapped private key.", e);
    	}
    	
    	return wrappedKey;
    }    
}
