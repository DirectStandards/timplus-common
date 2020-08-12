package org.directtruststandards.timplus.common.crypto.impl;

import java.security.KeyStore;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.directtruststandards.timplus.common.crypto.PKCS11Credential;
import org.directtruststandards.timplus.common.crypto.exceptions.CryptoException;

/**
 * Implementation of PKCS11 token store that generally does not get detached from the system.  Credentials are accessed via a PKCS11Credential implementation.
 * @author Greg Meyer
 * @since 1.0
 */
/// CLOVER:OFF
public class StaticPKCS11TokenKeyStoreProtectionManager extends AbstractPKCS11TokenKeyStoreProtectionManager
{
	@SuppressWarnings("deprecation")
	private static final Log LOGGER = LogFactory.getFactory().getInstance(StaticPKCS11TokenKeyStoreProtectionManager.class);	
	
	/**
	 * Empty constructor
	 * @throws CryptoException
	 */
	public StaticPKCS11TokenKeyStoreProtectionManager() throws CryptoException
	{
		super();
	}
	
	/**
	 * Constructs the store with a credential manager and aliases.
	 * @param credential The credentials to log into the store.
	 * @param keyStorePassPhraseAlias The alias name of the key store key in the PKCS11 token.
	 * @param privateKeyPassPhraseAlias The alias name of the private key protection key in the PKCS11 token.
	 * @throws CryptoException
	 */
	public StaticPKCS11TokenKeyStoreProtectionManager(PKCS11Credential credential, String keyStorePassPhraseAlias, String privateKeyPassPhraseAlias) throws CryptoException
	{
		super(credential, keyStorePassPhraseAlias, privateKeyPassPhraseAlias);
	}
	
	/**
	 * {@inheritDoc}
	 */
	public void initTokenStore() throws CryptoException
	{
		loadProvider();
		
		try
		{
			LOGGER.debug("Initializing token store type " + keyStoreType);
			ks = KeyStore.getInstance(keyStoreType);
			ks.load(keyStoreSource, credential.getPIN()); 
		}
		catch (Exception e)
		{
			throw new CryptoException("Error initializing PKCS11 token", e);
		}
	}
}
/// CLOVER:ON
